"""Multi-domain muhendislik algoritma tespiti.

Decompile edilmis C kodunda FEA, CFD, finans, ML, DSP algoritmalarini
tespit eder. Mevcut kripto dedektoruyle (CAlgorithmIdentifier) ayni
AlgorithmMatch arayuzunu kullanir.

Uc katmanli tespit:
1. Constant-Based: IEEE-754 sabitleri (Gauss noktalari, turb. sabitleri vs.)
2. Structure-Based: Kod yapisi pattern'leri (convergence loop, matrix op vs.)
3. API Correlation: BLAS/LAPACK/FFTW/PETSc fonksiyon cagrilari

v1.7.1: GPU removed -- CPU-only pipeline
"""
from __future__ import annotations

import bisect
import json
import logging
import math
import re
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import TYPE_CHECKING, Any

from karadul.config import CPU_PERF_CORES
from karadul.reconstruction.c_algorithm_id import (
    STRUCT_MIN_DISTINCT_KINDS,
    AlgorithmMatch,
    CAlgorithmResult,
    _code_only,
)
from karadul.reconstruction.engineering.constants import (
    ENGINEERING_CONSTANTS,
    HEX_LOOKUP,
    DECIMAL_PATTERNS,
    CONSTANT_GROUPS,
)
from karadul.reconstruction.engineering.patterns import ENGINEERING_PATTERNS
from karadul.reconstruction.engineering.apis import ENGINEERING_APIS, API_COMBINED_REGEX

if TYPE_CHECKING:
    from karadul.reconstruction.engineering.patterns import StructuralPattern

logger = logging.getLogger(__name__)

# Domain classification: category string -> domain index mapping.
# Her fonksiyon icin (K_DOMAINS,) probability vektoru hesaplanir.
_DOMAIN_NAMES = [
    "fea",        # 0: finite element, linear algebra, numerical solver
    "cfd",        # 1: turbulence, fluid dynamics
    "finance",    # 2: stochastic, option pricing
    "ml",         # 3: machine learning, optimization, activation
    "dsp",        # 4: signal processing, transforms, filters
    "other",      # 5: geometry, root finding, misc numerical
]
_NUM_DOMAINS = len(_DOMAIN_NAMES)

# Category -> domain index lookup.
_CATEGORY_TO_DOMAIN: dict[str, int] = {
    # FEA domain
    "linear_algebra": 0,
    "numerical_solver": 0,
    "nonlinear_solver": 0,
    "finite_element": 0,
    "fea_integration": 0,
    "fea_dynamics": 0,
    "time_integration": 0,
    "numerical_calculus": 0,
    # CFD domain
    "cfd_turbulence": 1,
    "cfd_flow": 1,
    "cfd_solver": 1,
    # Finance domain
    "stochastic": 2,
    "option_pricing": 2,
    "financial_math": 2,
    # ML domain
    "ml_optimization": 3,
    "ml_activation": 3,
    "ml_transformer": 3,
    "ml_inference": 3,
    # DSP domain
    "dsp_transform": 4,
    "dsp_filter": 4,
    "dsp_analysis": 4,
    # Other
    "geometry": 5,
    "root_finding": 5,
}

# ---------------------------------------------------------------------------
# Domain indicator sets for pre-filtering  (Issue #5, 2026-03-25)
# If NONE of these symbols are found in the function list, skip constant
# and structural pattern analysis.  API detection always runs (it's cheap
# and the word-boundary patterns are precise enough).
# ---------------------------------------------------------------------------

# FEA / linear algebra domain
_FEA_INDICATORS = frozenset({
    "dgemm", "sgemm", "dgetrf", "dgetrs", "dpotrf", "dsyev", "dgesvd",
    "dgesv", "daxpy", "ddot", "dnrm2", "dscal", "dgemv", "dtrsm", "dtrsv",
    "dsyrk", "dgeqrf", "dgels", "dgelsd", "dgbtrf", "dpbtrf", "dstev",
    "spooles", "pardiso", "arpack", "dsaupd", "dseupd", "mumps",
    "dmumps", "cholmod", "umfpack", "metis", "petsc",
    "kspsolve", "matassemblybegin", "snessolve", "tssolve",
    "mafill", "e_c3d", "nonlingeo", "calculix",
    "hypre", "epetra", "trilinos",
})

# DSP / signal processing domain
_DSP_INDICATORS = frozenset({
    "fftw", "fft", "ifft", "dft", "fftw_plan", "fftw_execute",
    "rfftw", "fftwf",
})

# Finance domain
_FINANCE_INDICATORS = frozenset({
    "quantlib", "black_scholes", "monte_carlo", "ql_",
    "black76", "heston", "yieldcurve",
})

# ML domain
_ML_INDICATORS = frozenset({
    "tensorflow", "torch", "caffe", "cudnn", "cublas", "cusolver",
    "cublaslt", "cudnnconv", "nccl",
    "mkl_dnn", "onednn",
})

# Combined: any scientific/engineering domain
_ALL_DOMAIN_INDICATORS = (
    _FEA_INDICATORS | _DSP_INDICATORS | _FINANCE_INDICATORS | _ML_INDICATORS
)

# ---------------------------------------------------------------------------
# Sabit ve yapısal katman kuralları (P04b, MUH-10; 2026-11-18)
# ---------------------------------------------------------------------------
# Eski sabit katmanı ondalık sabiti gövdede ALT DİZGİ olarak arıyordu
# (``"0" in code``): "0", "4", "6", "8" her gövdede bulunduğu için kapı açıldığında
# coreutils ``sort``'ta 1 384, 133 masum ikilide 307 448 sahte tespit (RC4, Halton,
# AES, SM4 …) çıkıyordu. 119 ikilide sessiz kalmasının tek nedeni bozuk alan
# kapısıydı (``func_meta.keys()`` = ``total/program/functions``).
#
# Yeni kural (``c_algorithm_id`` sabit katmanının düzeni, ab986da):
#   1. Sabit yalnız bütün bir kayan nokta belirteci (``0.5773502691896257``, ``1e-12``,
#      ``101325.0``; nokta ya da üs zorunlu) ya da 64 bitlik IEEE-754 bit deseni olarak
#      yazılmış onaltılık belirteç (``0x3fe279a74590331d``; 32 biti aşan) olarak eşleşir.
#      Tam sayı belirteci (``0``, ``4``, ``10``) double sabit değildir, kanıt sayılmaz.
#      Dizgi ve yorum içindekiler sayılmaz (``_code_only``).
#   2. Değer karşılaştırması sayısaldır: belirtecin mutlak değeri sabitinkine
#      ``ENG_CONST_REL_TOL`` göreli farkla eşit olmalı (``0.95`` ↛ ``0.953``).
#   3. Zayıf değerler hiçbir zaman kanıt değildir: 0, anlamlı basamağı
#      ``ENG_CONST_MIN_SIG_DIGITS``'ten az olanlar (0.1, 0.95, 1.4, 100, 1e-6) ve küçük
#      paydalı ikili kesirler / tam sayılar (``x * 256`` tam sayı ve ``|x| < 65536``:
#      0.5, 0.375, 2.25, 252, 1708) ve paydası 8'e kadar basit kesirler (1/3, 1/6, 2/3;
#      CalculiX'te 29 fonksiyona "RK4" yazdırıyordu).
#   4. Etiket için aynı fonksiyonda algoritmanın en az ``ENG_CONST_MIN_DISTINCT`` farklı
#      ayırt edici sabiti gerekir (``±x`` tek sabittir).
#
# Yapısal katman, ``c_algorithm_id._scan_structural``'ın (P06, TIP-09) kuralıyla:
#   desenler dizgi ve yorumları örtülmüş kodda koşar; yalnız ad / anahtar sözcük olan
#   desenler (``\bpid\b``, ``\berror\b``, ``\bvon\ mises\b``) kanıt değildir; etiket için
#   en az ``STRUCT_MIN_DISTINCT_KINDS`` farklı yapısal desen eşleşmeli.
#
# Alan kapısı: göstergeler fonksiyon adlarında (``ghidra_functions.json``'un
# ``functions`` listesi) ve ilk dosyaların kod tanımlayıcılarında TAM AD ya da ÖNEK
# belirteci olarak aranır (``fft`` ↛ ``_difftime``).

#: Etiket için aynı fonksiyonda gereken farklı ayırt edici sabit sayısı.
ENG_CONST_MIN_DISTINCT: int = 2
#: Bundan az anlamlı basamaklı değerler zayıftır (0.95, 1.4, 1e-6, 100).
ENG_CONST_MIN_SIG_DIGITS: int = 3
#: ``x * ENG_CONST_DYADIC_DENOM`` tam sayıysa ve ``|x| < ENG_CONST_DYADIC_MAX`` ise değer
#: zayıftır (0.5, 0.375, 2.25, tam sayılar).
ENG_CONST_DYADIC_DENOM: int = 256
ENG_CONST_DYADIC_MAX: float = 65536.0
#: Paydası bu değere kadar olan basit kesirler (1/3, 1/6, 2/3) zayıftır. 5/9 ve 8/9
#: (Gauss 3 nokta ağırlıkları) bu sınırın dışında kalır.
ENG_CONST_SIMPLE_RATIONAL_MAX_DENOM: int = 8
#: Kayan nokta belirteci ile sabit arasındaki en büyük göreli fark.
ENG_CONST_REL_TOL: float = 1e-6
#: Onaltılık belirteç ancak bu değeri aşarsa (64 bitlik alan) IEEE-754 deseni sayılır.
ENG_CONST_HEX_MIN: int = 0xFFFFFFFF
#: Alan göstergesi bu uzunlukta ya da daha uzunsa ad öneki olarak ayraçsız da eşleşir
#: (``mafill`` → ``mafillsm``); kısa göstergeler tam belirteç ister (``fft`` → ``fft_…``).
DOMAIN_INDICATOR_BARE_PREFIX_MIN: int = 6

_FLOAT_TOKEN_RE = re.compile(
    r"(?<![\w.])(?:\d+\.\d*(?:[eE][-+]?\d+)?|\.\d+(?:[eE][-+]?\d+)?|\d+[eE][-+]?\d+)"
    r"[fFlL]?(?![\w.])"
)
_HEX_TOKEN_RE = re.compile(r"(?<![\w.])0[xX]([0-9a-fA-F]+)(?:[uU]?[lL]{0,2})(?![\w.])")
_MASK64: int = (1 << 64) - 1


def _sig_digits(value: float) -> int:
    """Kısa ondalık gösterimde anlamlı basamak sayısı (``0.095`` → 2, ``101325.0`` → 6)."""
    mantissa = repr(abs(value)).lower().split("e")[0].replace(".", "")
    return len(mantissa.strip("0"))


def is_weak_double(value: float) -> bool:
    """Tek başına hiçbir algoritmayı göstermeyen double değer mi (kural 3)?"""
    if not math.isfinite(value) or value == 0.0:
        return True
    mag = abs(value)
    if _sig_digits(mag) < ENG_CONST_MIN_SIG_DIGITS:
        return True
    if (mag * ENG_CONST_DYADIC_DENOM).is_integer() and mag < ENG_CONST_DYADIC_MAX:
        return True
    # Küçük paydalı basit kesir (1/3, 1/6, 2/3, 3/7): gövdede her türlü oranda geçer.
    simple = Fraction(mag).limit_denominator(ENG_CONST_SIMPLE_RATIONAL_MAX_DENOM)
    return (
        mag < ENG_CONST_DYADIC_MAX
        and abs(float(simple) - mag) <= mag * ENG_CONST_REL_TOL
    )


def _magnitude_key(value: float) -> str:
    return f"{abs(value):.9g}"


# Ayırt edici sabitlerin büyüklük dizini (zayıflar dışarıda); ikili arama için sıralı.
_STRONG_CONSTANTS = sorted(
    ((abs(c.float_value), c) for c in ENGINEERING_CONSTANTS if not is_weak_double(c.float_value)),
    key=lambda t: t[0],
)
_STRONG_MAGNITUDES = [m for m, _c in _STRONG_CONSTANTS]


def _constants_near(magnitude: float) -> list:
    """``magnitude``'a ``ENG_CONST_REL_TOL`` içinde eşit ayırt edici sabitler."""
    if magnitude <= 0.0 or not math.isfinite(magnitude):
        return []
    lo = bisect.bisect_left(_STRONG_MAGNITUDES, magnitude * (1.0 - ENG_CONST_REL_TOL))
    hi = bisect.bisect_right(_STRONG_MAGNITUDES, magnitude * (1.0 + ENG_CONST_REL_TOL))
    return [c for _m, c in _STRONG_CONSTANTS[lo:hi]]


# Ad / anahtar sözcük deseni tanıma: kaçışlar, sözcük sınırı, boşluk ve grup sözdizimi
# atılınca geriye yalnız harf / rakam / alt çizgi kalıyorsa desen bir ad aramasıdır.
_KEYWORD_REGEX_NOISE = re.compile(
    r"\\[ \-]|\(\?[aiLmsux]+\)|\\b|\\s[*+?]?|\\w[*+?]?|\[_\\s\][*+?]?|_\?|\(\?:|[()|?]"
)


def is_keyword_regex(pattern: str) -> bool:
    """Desen yalnız bir ad / anahtar sözcük / sözcük öbeği mi arıyor (kod yapısı değil)?"""
    rest = _KEYWORD_REGEX_NOISE.sub("", pattern)
    return bool(rest) and re.fullmatch(r"[A-Za-z0-9_]+", rest) is not None


_NAME_PART_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def _indicator_matches(name: str, indicator: str) -> bool:
    """Alan göstergesi adın tamamı ya da önek belirteci mi (alt dizgi değil)?

    ``dgemm_`` / ``_dgemm_`` → ``dgemm`` (tam ad), ``fftw_execute`` → ``fftw`` (``_`` ayracı),
    ``PetscInitialize`` → ``petsc`` (camelCase belirteci), ``mafillsm`` → ``mafill`` (uzun
    gösterge, ayraçsız önek). ``_difftime`` ↛ ``fft``.
    """
    norm = name.strip("_").lower()
    ind = indicator.strip("_")
    if not norm or not ind:
        return False
    if norm == ind or norm.startswith(ind + "_"):
        return True
    if len(ind) >= DOMAIN_INDICATOR_BARE_PREFIX_MIN and norm.startswith(ind):
        return True
    parts = [w.lower() for seg in name.split("_") if seg for w in _NAME_PART_RE.findall(seg)]
    return bool(parts) and parts[0] == ind


def _function_names(func_meta: dict[str, Any]) -> list[str]:
    """``ghidra_functions.json`` biçimlerinden fonksiyon adları.

    Bugünkü biçim ``{"total", "program", "functions": [{"name", "address", …}]}``;
    eski biçim ad → bilgi sözlüğü (``_load_json`` listeyi de bu biçime çevirir).
    """
    funcs = func_meta.get("functions") if isinstance(func_meta, dict) else None
    if isinstance(funcs, list):
        return [str(f.get("name", "")) for f in funcs if isinstance(f, dict) and f.get("name")]
    return [k for k, v in (func_meta or {}).items() if isinstance(v, (dict, str))]


# Ghidra decompile ciktisi fonksiyon baslangic pattern'i
# CAlgorithmIdentifier._FUNC_RE ile ayni, buraya kopyalanarak
# import bagimliligini azaltiyoruz.
_FUNC_RE = re.compile(
    r"^(?:(?:void|int|uint|long|ulong|char|uchar|short|ushort|byte|bool|float|double|"
    r"size_t|ssize_t|undefined\d?|code\s*\*|undefined\s*\*|"
    r"\w+\s*\*+)\s+)"
    r"(\w+)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)

# Structural-only confidence cap -- yapi tespiti tek basina yuksek
# guven vermez, constant veya API kaniti ile desteklenmeli.
_STRUCTURAL_ONLY_CAP = 0.50

# ---------------------------------------------------------------------------
# v1.6.2: ProcessPoolExecutor worker -- GIL-free paralel regex taramasi
# ---------------------------------------------------------------------------
# Python GIL regex C extension'larini da bloklar.
# ThreadPoolExecutor regex islerinde hic paralellik saglamaz.
# ProcessPoolExecutor ile her worker kendi GIL'inde calisir = gercek paralel.

_worker_analyzer: "EngineeringAlgorithmAnalyzer | None" = None


def _worker_init() -> None:
    """ProcessPoolExecutor worker'i baslarken analyzer instance olustur."""
    global _worker_analyzer
    _worker_analyzer = EngineeringAlgorithmAnalyzer()


def _worker_analyze_file(
    args: tuple[Path, dict, bool],
) -> list:
    """Worker process'te tek dosya analiz et."""
    filepath, func_meta, has_domain = args
    global _worker_analyzer
    if _worker_analyzer is None:
        _worker_init()
    assert _worker_analyzer is not None  # _worker_init() sonrasi garantili
    return _worker_analyzer._analyze_file(filepath, func_meta, has_domain)

# Noisy-OR birlestirmede ust sinir.  Asla %100 deme.
_NOISY_OR_CAP = 0.98

# Yuksek guven esigi: en az constant + API gerek.
_HIGH_CONFIDENCE_THRESHOLD = 0.70

# BUG #14: Tek-kanit "constant" tespiti (capraz kanit + ikinci sabit YOK)
# naming candidate uretimine gidecek kadar guvenilir degil (FP riski).
# Bu tavan, naming floor'un (bkz pipeline/steps/_feedback_naming_candidates.py,
# engineering_constant floor = 0.40) ALTINDA tutulur; boylece izole tek sabit
# naming'e sizmaz ama match istatistik/annotation icin gorunur kalir.
# Cok-kanitli (2+ sabit veya cross-method) tespitler bundan ETKILENMEZ.
_CONSTANT_ONLY_SINGLE_CAP = 0.39


class EngineeringAlgorithmAnalyzer:
    """Multi-domain engineering algorithm detector.

    CAlgorithmIdentifier ile ayni 3-katmanli mimariyi kullanir:
    - Layer 1: IEEE-754 constant detection  (HEX_LOOKUP + DECIMAL_PATTERNS)
    - Layer 2: Structural pattern matching  (ENGINEERING_PATTERNS)
    - Layer 3: API correlation              (ENGINEERING_APIS + API_COMBINED_REGEX)

    Tum katmanlarin sonuclari Noisy-OR ile birlestirilip tek confidence
    skoruna indirgenir.  Ayni (fonksiyon, algoritma) cifti birden fazla
    katmandan tespit edilirse guven artar.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Pre-compile hex lookup -- sabitleri hizli aramak icin.
        # HEX_LOOKUP: {hex_string_lower: [(algo_name, category, group, base_confidence), ...]}
        self._hex_lookup = HEX_LOOKUP
        # Pre-compile decimal patterns
        # DECIMAL_PATTERNS: [(compiled_regex, algo_name, category, group, base_confidence), ...]
        self._decimal_patterns = DECIMAL_PATTERNS
        # Constant groups: {group_name: [algo_names]}
        self._constant_groups = CONSTANT_GROUPS
        # Structural patterns list
        self._structural_patterns = ENGINEERING_PATTERNS
        # API dict & combined regex
        # API dict: her regex pattern -> APISignature
        # Match sonucunu geriye eslestirmek icin compiled pattern listesi tutuluyor
        self._api_list = ENGINEERING_APIS
        self._api_regex = API_COMBINED_REGEX
        # Pre-compile individual patterns for reverse lookup
        self._api_compiled = [
            (re.compile(api.pattern, re.IGNORECASE), api)
            for api in ENGINEERING_APIS
        ]
        # Structural pattern anchor keywords -- pre-filter icin
        # Her pattern icin regex'teki literal kelimeleri cikarip cache'le.
        # Fonksiyon body'sinde anchor keyword yoksa regex'i calistirmaya
        # gerek yok (468 pattern * her fonksiyon -> cok pahali).
        #
        # Per-regex anchor: her regex icin AYRI anchor set.
        # Pattern calistirilmali eger herhangi bir regex'in anchor'u
        # kodda bulunuyorsa VEYA o regex'in anchor seti bos ise.
        self._structural_anchors: list[list[frozenset[str]]] = []
        for sp in ENGINEERING_PATTERNS:
            per_regex_anchors = _extract_per_regex_anchors(sp)
            self._structural_anchors.append(per_regex_anchors)
        # P04b: yalnız yapısal (ad / anahtar sözcük olmayan) regex'ler, çapalarıyla.
        self._structural_regexes: list[list[tuple[re.Pattern[str], frozenset[str]]]] = [
            [
                (regex, anchors)
                for regex, anchors in zip(sp.patterns, self._structural_anchors[i])
                if not is_keyword_regex(regex.pattern)
            ]
            for i, sp in enumerate(ENGINEERING_PATTERNS)
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def identify(
        self,
        decompiled_dir: Path,
        functions_json: Path,
        strings_json: Path | None = None,
    ) -> CAlgorithmResult:
        """Scan all decompiled files and detect engineering algorithms.

        Args:
            decompiled_dir: Ghidra decompile ciktisinin bulundugu dizin.
            functions_json: Fonksiyon metadata JSON (adres, boyut vb.).
            strings_json: String referanslari (opsiyonel, kullanilmiyor henuz).

        Returns:
            CAlgorithmResult: Tespit sonuclari -- mevcut kripto dedektoru ile
            ayni arayuzu kullanir.
        """
        errors: list[str] = []
        all_matches: list[AlgorithmMatch] = []

        # Fonksiyon metadata yukle
        func_meta = self._load_json(functions_json, errors)

        # C dosyalarini topla
        c_files = self._collect_c_files(decompiled_dir, errors)
        if not c_files:
            return CAlgorithmResult(
                success=False,
                errors=errors or ["No C files found in decompiled directory"],
            )

        # ------------------------------------------------------------------
        # Domain pre-filtering (Issue #5, 2026-03-25)
        # Scan function names for domain indicators.  If no scientific
        # library symbols are found, skip expensive constant and structural
        # pattern scanning -- only run API detection (which is cheap and
        # precise thanks to word-boundary patterns).
        # ------------------------------------------------------------------
        has_domain = self._detect_domain(func_meta, c_files)
        if not has_domain:
            logger.info(
                "No scientific domain indicators found -- "
                "skipping constant/structural analysis (API-only mode)"
            )

        # v1.6.2: ProcessPoolExecutor -- GIL-free paralel regex taramasi.
        # ThreadPoolExecutor regex C extension'da GIL tuttugundan
        # hic paralellik saglamiyordu. ProcessPool ile gercek paralel.
        processed = 0
        total = len(c_files)
        n_workers = min(CPU_PERF_CORES, total)

        logger.info(
            "Engineering algorithm scan: %d files, %d workers (ProcessPool)",
            total, n_workers,
        )

        try:
            with ProcessPoolExecutor(
                max_workers=n_workers,
                initializer=_worker_init,
            ) as pool:
                args_list = [(f, func_meta, has_domain) for f in c_files]
                for file_matches in pool.map(
                    _worker_analyze_file, args_list, chunksize=50,
                ):
                    processed += 1
                    all_matches.extend(file_matches)
                    if processed % 500 == 0:
                        logger.info(
                            "  Engineering scan progress: %d/%d (%.0f%%)",
                            processed, total, 100.0 * processed / total,
                        )
        except Exception as exc:
            # ProcessPool basarisiz olursa ThreadPool'a fallback
            logger.warning(
                "ProcessPool basarisiz, ThreadPool fallback: %s", exc,
            )
            with ThreadPoolExecutor(max_workers=n_workers) as pool:
                futures = {
                    pool.submit(self._analyze_file, f, func_meta, has_domain): f
                    for f in c_files
                }
                for future in as_completed(futures):
                    processed += 1
                    try:
                        file_matches = future.result()
                        all_matches.extend(file_matches)
                    except Exception as e2:
                        errors.append(f"Engineering analysis: {e2}")

        # v1.7.1: GPU removed -- CPU-only pipeline
        combined = self._combine_evidence(all_matches)

        # Tekillestirilme
        deduplicated = self._deduplicate(combined)

        # CPU domain classification -- her fonksiyon icin
        # domain probability vektoru.
        domain_info = self._classify_domains(deduplicated)
        if domain_info:
            # Log dominant domains
            domain_summary: dict[str, int] = {}
            for func_name, domain_probs in domain_info.items():
                if domain_probs:
                    top_domain = domain_probs[0][0]
                    domain_summary[top_domain] = domain_summary.get(top_domain, 0) + 1
            if domain_summary:
                logger.info(
                    "Domain classification: %s",
                    ", ".join(f"{d}={c}" for d, c in sorted(
                        domain_summary.items(), key=lambda x: -x[1]
                    )),
                )

        # Istatistik
        by_category: dict[str, int] = {}
        by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}

        for m in deduplicated:
            by_category[m.category] = by_category.get(m.category, 0) + 1
            if m.confidence >= 0.7:
                by_confidence["high"] += 1
            elif m.confidence >= 0.4:
                by_confidence["medium"] += 1
            else:
                by_confidence["low"] += 1

        logger.info(
            "Engineering algorithms: %d detected (%d high, %d medium, %d low)",
            len(deduplicated),
            by_confidence["high"],
            by_confidence["medium"],
            by_confidence["low"],
        )

        return CAlgorithmResult(
            success=True,
            algorithms=deduplicated,
            total_detected=len(deduplicated),
            by_category=by_category,
            by_confidence=by_confidence,
            errors=errors,
            domain_classification=domain_info,
        )

    # ------------------------------------------------------------------
    # File-level analysis
    # ------------------------------------------------------------------

    def _analyze_file(
        self, filepath: Path, func_meta: dict, has_domain: bool = True,
    ) -> list[AlgorithmMatch]:
        """Analyze a single decompiled C file.

        Dosya icerigini okur, fonksiyonlara boler, her fonksiyona
        3 katmanli tarama uygular.

        Args:
            has_domain: If False, skip constant and structural scanning
                (domain pre-filter found no scientific indicators).
        """
        file_matches: list[AlgorithmMatch] = []
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("Cannot read %s: %s", filepath.name, exc)
            return file_matches

        functions = self._extract_functions(content, func_meta, filepath.stem)

        for func_name, func_body, func_addr in functions:
            try:
                # API detection always runs (precise, cheap)
                api_hits = self._scan_apis(func_body, func_name, func_addr)
                file_matches.extend(api_hits)

                # Constant and structural scanning only if domain indicators found
                if has_domain:
                    const_hits = self._scan_constants(func_body, func_name, func_addr)
                    struct_hits = self._scan_structural(func_body, func_name, func_addr)
                    file_matches.extend(const_hits)
                    file_matches.extend(struct_hits)
            except Exception as exc:
                logger.debug(
                    "Engineering scan error (%s in %s): %s",
                    func_name, filepath.name, exc,
                )

        return file_matches

    # ------------------------------------------------------------------
    # Layer 1: IEEE-754 constant detection
    # ------------------------------------------------------------------

    def _scan_constants(
        self, code: str, func_name: str, address: str,
    ) -> list[AlgorithmMatch]:
        """Layer 1: IEEE-754 sabit tespiti (kurallar dosya başında, P04b / MUH-10).

        Sabit yalnız bütün kayan nokta belirteci ya da 64 bitlik IEEE-754 bit deseni
        (onaltılık) olarak, dizgi ve yorum dışında eşleşir; zayıf değerler kanıt
        değildir; etiket için aynı fonksiyonda algoritmanın en az
        ``ENG_CONST_MIN_DISTINCT`` farklı ayırt edici sabiti gerekir.

        Ornek:
            ``x = 0.7745966692414834 * a + 0.5555555555555556 * b`` → Gauss 3 nokta
            (iki ayırt edici sabit); ``if (x == 0) y = 4;`` → hiçbir şey.
        """
        clean = _code_only(code)
        # (algoritma, kategori) -> {büyüklük anahtarı: kanıt}; aynı anahtar bir kez sayılır (±x).
        found: dict[tuple[str, str], dict[str, str]] = {}
        best_conf: dict[tuple[str, str], float] = {}

        def _add(ec: Any, evidence: str) -> None:
            key = (ec.algorithm, ec.category)
            found.setdefault(key, {}).setdefault(_magnitude_key(ec.float_value), evidence)
            best_conf[key] = max(best_conf.get(key, 0.0), ec.confidence)

        for m in _FLOAT_TOKEN_RE.finditer(clean):
            token = m.group(0)
            try:
                value = float(token.rstrip("fFlL"))
            except ValueError:
                continue
            for ec in _constants_near(abs(value)):
                _add(ec, f"float: {token} ({ec.description})")

        for m in _HEX_TOKEN_RE.finditer(clean):
            raw = int(m.group(1), 16)
            if raw <= ENG_CONST_HEX_MIN or raw > _MASK64:
                continue
            for ec in self._hex_lookup.get(f"{raw:016x}", ()):
                if is_weak_double(ec.float_value):
                    continue
                _add(ec, f"hex: 0x{raw:016x} ({ec.description})")

        matches: list[AlgorithmMatch] = []
        for (algo_name, category), evidence_by_value in found.items():
            distinct = len(evidence_by_value)
            if distinct < ENG_CONST_MIN_DISTINCT:
                continue
            conf = min(
                0.90,
                best_conf[(algo_name, category)]
                + 0.05 * min(distinct - ENG_CONST_MIN_DISTINCT, 4),
            )
            matches.append(AlgorithmMatch(
                name=algo_name,
                category=category,
                confidence=round(conf, 3),
                detection_method="constant",
                evidence=list(evidence_by_value.values())[:10],
                function_name=func_name,
                address=address,
            ))
        return matches

    # ------------------------------------------------------------------
    # Layer 2: Structural pattern detection
    # ------------------------------------------------------------------

    def _scan_structural(
        self, code: str, func_name: str, address: str,
    ) -> list[AlgorithmMatch]:
        """Layer 2: Yapısal desen tespiti (``c_algorithm_id`` yapısal kuralıyla, P04b).

        Desenler dizgi ve yorumları örtülmüş kodda (``_code_only``) koşar. Yalnız ad /
        anahtar sözcük arayan desenler (``is_keyword_regex``) kanıt değildir; etiket için
        en az ``STRUCT_MIN_DISTINCT_KINDS`` farklı yapısal desen ve toplamda
        ``min_matches`` eşleşme gerekir. Yapısal tespit tek başına
        ``_STRUCTURAL_ONLY_CAP`` güveni aşmaz.

        Optimizasyon: her yapısal regex için çapa sözcükleri; çapası kodda olmayan regex
        koşmaz.
        """
        matches: list[AlgorithmMatch] = []
        clean = _code_only(code)
        code_lower = clean.lower()

        for idx, sp in enumerate(self._structural_patterns):
            regexes = self._structural_regexes[idx]
            if len(regexes) < STRUCT_MIN_DISTINCT_KINDS:
                continue

            kinds = 0
            total_hits = 0
            evidence: list[str] = []
            seen_spans: set[tuple[int, int]] = set()
            for regex, anchors in regexes:
                if anchors and not any(a in code_lower for a in anchors):
                    continue
                spans = [m.span() for m in regex.finditer(clean)]
                if not spans:
                    continue
                total_hits += len(spans)
                # Başka bir desenin eşleştiği metnin aynısı ayrı kanıt türü değildir.
                new_spans = [sp_ for sp_ in spans if sp_ not in seen_spans]
                seen_spans.update(spans)
                if not new_spans:
                    continue
                kinds += 1
                start, end = new_spans[0]
                evidence.append(f"{sp.name}: matched '{clean[start:end][:80]}'")

            if kinds < STRUCT_MIN_DISTINCT_KINDS or total_hits < sp.min_matches:
                continue

            # Base confidence from pattern definition
            base_conf = sp.confidence
            # Bonus per extra hit beyond minimum
            bonus = min(0.20, 0.03 * (total_hits - sp.min_matches))
            conf = min(base_conf + bonus, _STRUCTURAL_ONLY_CAP)

            matches.append(AlgorithmMatch(
                name=sp.algorithm,
                category=sp.category,
                confidence=round(conf, 3),
                detection_method="structural",
                evidence=evidence[:5],
                function_name=func_name,
                address=address,
            ))

        return matches

    # ------------------------------------------------------------------
    # Layer 3: API correlation detection
    # ------------------------------------------------------------------

    def _scan_apis(
        self, code: str, func_name: str, address: str,
    ) -> list[AlgorithmMatch]:
        """Layer 3: API correlation detection.

        API_COMBINED_REGEX ile tek geciste tum API cagrilarini bulur.
        Her API eslesmesi yuksek guven (0.85-0.95) verir cunku
        fonksiyon isimleri cok spesifiktir.
        """
        matches: list[AlgorithmMatch] = []
        if self._api_regex is None:
            return matches

        seen: set[str] = set()

        # Tek gecis: combined regex ile olasi match pozisyonlarini bul
        for m in self._api_regex.finditer(code):
            matched_text = m.group(0)
            # Hangi API'ye ait oldugunu bul (reverse lookup)
            info = None
            for pat_re, api_sig in self._api_compiled:
                if pat_re.fullmatch(matched_text):
                    info = api_sig
                    break
            if info is None:
                continue

            algo = info.algorithm
            key = f"{algo}:{func_name}"
            if key in seen:
                continue
            seen.add(key)

            matches.append(AlgorithmMatch(
                name=algo,
                category=info.category,
                confidence=info.confidence,
                detection_method="api",
                evidence=[f"API call: {matched_text} ({info.library})"],
                function_name=func_name,
                address=address,
            ))

        return matches

    # ------------------------------------------------------------------
    # Evidence combination (Noisy-OR)
    # ------------------------------------------------------------------

    def _combine_evidence(
        self, matches: list[AlgorithmMatch],
    ) -> list[AlgorithmMatch]:
        """Combine multi-layer evidence using Noisy-OR.

        Ayni (function_name, algorithm_name) cifti birden fazla layer'dan
        tespit edildiyse:

            P(algo) = 1 - prod(1 - p_i)

        Bu formul her layer'in bagimsiz bir "sensor" gibi davrandigini
        varsayar.  Ornegin constant=0.6 ve structural=0.4 birlestiginde:

            P = 1 - (1-0.6)*(1-0.4) = 1 - 0.24 = 0.76

        Ek kural: structural-only tespit (constant/api kaniti olmadan)
        _STRUCTURAL_ONLY_CAP ile sinirli kalir.

        Ek kural: _HIGH_CONFIDENCE_THRESHOLD (0.70) ustune cikmak icin
        en az 2 farkli detection_method veya constant+api birlikteligi gerekir.
        """
        # Group by (function_name, normalized algorithm name)
        groups: dict[tuple[str, str], list[AlgorithmMatch]] = {}
        for m in matches:
            key = (m.function_name, m.name.lower().strip())
            groups.setdefault(key, []).append(m)

        combined: list[AlgorithmMatch] = []

        for (fn, algo_key), group in groups.items():
            if len(group) == 1:
                single = group[0]
                # BUG #14: Corroboration sarti -- tek-kanit "constant" tespiti
                # (bu match icin baska katman ve ikinci bir sabit YOK) capraz
                # kanit olmadan naming'e gidecek kadar guvenilir degil.
                # len(evidence) < 2 => tek izole sabit => guveni naming
                # floor'un altina cek (FP kes). 2+ sabitli veya cok-katmanli
                # match'ler bu daldan gecmez / etkilenmez.
                if (
                    single.detection_method == "constant"
                    and len(single.evidence) < 2
                ):
                    single.confidence = min(
                        single.confidence, _CONSTANT_ONLY_SINGLE_CAP,
                    )
                combined.append(single)
                continue

            # Collect detection methods
            methods: set[str] = set()
            all_evidence: list[str] = []
            for m in group:
                methods.add(m.detection_method)
                for ev in m.evidence:
                    if ev not in all_evidence:
                        all_evidence.append(ev)

            # Noisy-OR fusion
            prob_miss = 1.0
            for m in group:
                prob_miss *= (1.0 - m.confidence)
            fused = 1.0 - prob_miss

            # Structural-only cap
            if methods == {"structural"}:
                fused = min(fused, _STRUCTURAL_ONLY_CAP)

            # High confidence requires multi-method evidence
            has_constant = "constant" in methods
            has_api = "api" in methods
            has_structural = "structural" in methods

            if fused >= _HIGH_CONFIDENCE_THRESHOLD:
                if len(methods) < 2 and not (has_constant and has_api):
                    # Tek method ile 0.70 ustu -- izin verme
                    # (api tek basina 0.85+ olabilir, ona izin ver)
                    if not has_api:
                        fused = min(fused, _HIGH_CONFIDENCE_THRESHOLD - 0.01)

            # Cap
            fused = min(fused, _NOISY_OR_CAP)

            # Use highest-confidence match as template
            best = max(group, key=lambda x: x.confidence)
            method_str = "+".join(sorted(methods))

            combined.append(AlgorithmMatch(
                name=best.name,
                category=best.category,
                confidence=round(fused, 3),
                detection_method=method_str,
                evidence=all_evidence[:15],
                function_name=best.function_name,
                address=best.address,
            ))

        return combined

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _deduplicate(
        self, matches: list[AlgorithmMatch],
    ) -> list[AlgorithmMatch]:
        """Remove duplicate detections, keep highest confidence.

        Ayni fonksiyon icinde ayni algoritma birden fazla kez bulunmussa
        (ornegin farkli constant'lar ayni algoritmaya isaret ediyorsa)
        en yuksek confidence'li olani tut.
        """
        best: dict[tuple[str, str], AlgorithmMatch] = {}

        for m in matches:
            key = (m.function_name, m.name.lower().strip())
            if key not in best or m.confidence > best[key].confidence:
                best[key] = m
            elif m.confidence == best[key].confidence:
                # Ayni confidence -- evidence birlestir
                existing = best[key]
                for ev in m.evidence:
                    if ev not in existing.evidence:
                        existing.evidence.append(ev)
                # Method birlestir
                for method in m.detection_method.split("+"):
                    if method not in existing.detection_method:
                        existing.detection_method += f"+{method}"

        # Confidence'a gore sirala
        return sorted(best.values(), key=lambda x: -x.confidence)

    # ------------------------------------------------------------------
    # Domain classification (CPU)  -- v1.7.1
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_domains(
        matches: list[AlgorithmMatch],
    ) -> dict[str, list[tuple[str, float]]] | None:
        """CPU domain classification per function.

        Her fonksiyon icin {domain_name: probability} vektoru hesaplar.
        Category -> domain mapping ile weighted accumulation, L1-normalize.

        Returns:
            {func_name: [(domain_name, probability), ...]} sorted by prob desc.
            None if no matches.
        """
        if not matches:
            return None

        # Fonksiyon -> index mapping
        func_names: list[str] = []
        func_to_idx: dict[str, int] = {}
        for m in matches:
            if m.function_name not in func_to_idx:
                func_to_idx[m.function_name] = len(func_names)
                func_names.append(m.function_name)

        n_funcs = len(func_names)
        if n_funcs == 0:
            return {}

        # Score accumulation: (n_funcs, _NUM_DOMAINS)
        scores = [[0.0] * _NUM_DOMAINS for _ in range(n_funcs)]
        for m in matches:
            fidx = func_to_idx[m.function_name]
            didx = _CATEGORY_TO_DOMAIN.get(m.category, _NUM_DOMAINS - 1)
            scores[fidx][didx] += m.confidence

        # L1-normalize per function
        result: dict[str, list[tuple[str, float]]] = {}
        for i, func_name in enumerate(func_names):
            row_sum = sum(scores[i])
            if row_sum < 1e-8:
                continue
            domain_probs = [
                (_DOMAIN_NAMES[d], round(scores[i][d] / row_sum, 4))
                for d in range(_NUM_DOMAINS)
                if scores[i][d] / row_sum > 0.001
            ]
            domain_probs.sort(key=lambda x: -x[1])
            result[func_name] = domain_probs

        return result

    # ------------------------------------------------------------------
    # Domain pre-filtering
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_domain(
        func_meta: dict[str, Any],
        c_files: list[Path],
    ) -> bool:
        """İkilide bilimsel / mühendislik kitaplığı göstergesi var mı (alan kapısı)?

        Göstergeler fonksiyon adlarında (``_function_names``: ``ghidra_functions.json``'un
        ``functions`` listesi) ve ilk 10 C dosyasının ilk ~50 KB'ındaki kod
        tanımlayıcılarında (dizgi / yorum dışı) TAM AD ya da ÖNEK belirteci olarak aranır
        (``_indicator_matches``; ``fft`` ↛ ``_difftime``).

        True ise sabit ve yapısal katman da koşar; False ise yalnız API katmanı.
        """
        indicators = sorted(_ALL_DOMAIN_INDICATORS)

        def _hit(names: Any) -> str | None:
            for name in names:
                for indicator in indicators:
                    if _indicator_matches(name, indicator):
                        return f"{indicator} <- {name}"
            return None

        # 1. Fonksiyon adları
        found = _hit(_function_names(func_meta or {}))
        if found:
            logger.debug("Domain indicator in function names: %s", found)
            return True

        # 2. İlk dosyaların kod tanımlayıcıları (ithal edilen çağrılar)
        for f in c_files[:10]:
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    text = _code_only(fh.read(50_000))
            except OSError:
                continue
            found = _hit(set(re.findall(r"[A-Za-z_]\w*", text)))
            if found:
                logger.debug("Domain indicator in %s: %s", f.name, found)
                return True

        return False

    # ------------------------------------------------------------------
    # Helpers -- file/function extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_c_files(
        directory: Path, errors: list[str],
    ) -> list[Path]:
        """Dizindeki C dosyalarini topla (recursive)."""
        if not directory.exists():
            errors.append(f"Directory does not exist: {directory}")
            return []
        files: list[Path] = []
        seen: set[Path] = set()
        for ext in ("*.c", "*.h", "*.cpp", "*.cc"):
            for f in directory.rglob(ext):
                resolved = f.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    files.append(f)
        return sorted(files)

    @staticmethod
    def _load_json(
        path: Path | None, errors: list[str],
    ) -> dict[str, Any]:
        """JSON dosyasini yukle, hata olursa bos dict dondur."""
        if path is None or not path.exists():
            return {}
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            # functions_json bazen list olabiliyor -- dict'e cevir
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
            errors.append(f"Cannot load {path.name}: {exc}")
            return {}

    @staticmethod
    def _extract_functions(
        content: str,
        func_meta: dict[str, Any],
        file_stem: str,
    ) -> list[tuple[str, str, str]]:
        """C iceriginden (func_name, func_body, address) cikar.

        Ghidra decompile ciktisi tipik format:
            void FUN_00401000(int param_1, ...) {
                ...
            }
        """
        results: list[tuple[str, str, str]] = []

        for match in _FUNC_RE.finditer(content):
            func_name = match.group(1)

            # Body cikarma -- brace matching
            body = _extract_body(content, match.end() - 1)

            # Adres: metadata'dan veya FUN_ prefix'inden
            address = "unknown"
            if func_name in func_meta:
                meta = func_meta[func_name]
                if isinstance(meta, dict):
                    address = meta.get("address", "unknown")
                elif isinstance(meta, str):
                    address = meta
            elif func_name.startswith("FUN_"):
                address = "0x" + func_name[4:]

            results.append((func_name, body, address))

        # Hic fonksiyon bulunamadiysa tum icerigi tek fonksiyon olarak al
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


def _extract_body(content: str, brace_pos: int) -> str:
    """Suslu parantez eslestirme ile fonksiyon body'sini cikart.

    Maks 5000 karakter okur -- buyuk fonksiyonlarda body'nin tamami
    gerekmez, ilk 5KB yeterli.
    """
    if brace_pos >= len(content) or content[brace_pos] != "{":
        return ""

    depth = 0
    limit = min(brace_pos + 5000, len(content))

    for i in range(brace_pos, limit):
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[brace_pos : i + 1]

    return content[brace_pos:limit]


# ---------------------------------------------------------------------------
# Structural pattern pre-filter: anchor keyword extraction
# ---------------------------------------------------------------------------

# C dili keyword'leri -- bunlar her kodda bulunur, pre-filter YAPMAZ
_C_KEYWORDS = frozenset({
    "for", "while", "if", "do", "else", "return", "break", "continue",
    "case", "switch", "void", "int", "long", "double", "float", "char",
    "unsigned", "signed", "short", "struct", "typedef", "const", "static",
    "extern", "sizeof", "null", "true", "false", "uint", "ulong", "bool",
    "byte", "size", "ssize", "undefined",
    # C stdlib -- her kodda bulunur, anchor olarak deger tashimaz
    "exp", "log", "sin", "cos", "sqrt", "fabs", "abs", "fabsf",
    "pow", "floor", "ceil", "atan", "atan2", "acos", "asin", "tan",
    "malloc", "calloc", "realloc", "free", "memset", "memcpy", "memmove",
    "strlen", "strcmp", "strcpy", "strcat", "printf", "sprintf", "fprintf",
    "rand", "srand",
})

# Regex meta-kelimeleri -- literal degil
_REGEX_META = frozenset({
    "dotall", "ignorecase", "multiline", "ascii", "verbose",
})


def _extract_regex_anchors(pat_str: str) -> frozenset[str]:
    """Tek bir regex pattern'inden anchor keyword'leri cikar.

    Args:
        pat_str: Regex pattern string'i.

    Returns:
        frozenset of lowercase anchor keywords.
        Bos set = pre-filter yok (her zaman calistir).
    """
    # Regex escape sequence'lerini temizle:
    # \b -> bos (word boundary), \s -> bos (whitespace),
    # \w -> bos (word char), \d -> bos (digit), vb.
    cleaned = re.sub(r"\\[bBswWdDAZ]", " ", pat_str)
    # Diger escape'ler: \., \*, \+, vb.
    cleaned = re.sub(r"\\(.)", r"\1", cleaned)
    # Regex character class ve quantifier'lari temizle
    cleaned = re.sub(r"\[[^\]]*\]", " ", cleaned)
    cleaned = re.sub(r"[{}()|?*+^$]", " ", cleaned)

    # 2+ harfli literal kelimeleri bul
    literals = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]+", cleaned)
    anchors: set[str] = set()
    for lit in literals:
        low = lit.lower()
        if low not in _C_KEYWORDS and low not in _REGEX_META:
            anchors.add(low)

    return frozenset(anchors)


def _extract_per_regex_anchors(
    sp: "StructuralPattern",
) -> list[frozenset[str]]:
    """Bir StructuralPattern'deki her regex icin AYRI anchor keyword seti cikar.

    Her regex'in kendi anchor set'i var. Pattern calistirilmali eger
    herhangi bir regex'in anchor kosulunu sagliyorsa:
    - Anchor bos ise: her zaman calistir (genel pattern)
    - Anchor dolu ise: en az biri kodda olmali

    Args:
        sp: StructuralPattern instance.

    Returns:
        list of frozensets -- her regex icin bir anchor set.
    """
    per_regex: list[frozenset[str]] = []

    for pat in sp.patterns:
        pat_str = pat.pattern if hasattr(pat, "pattern") else str(pat)
        anchors = _extract_regex_anchors(pat_str)
        per_regex.append(anchors)

    return per_regex
