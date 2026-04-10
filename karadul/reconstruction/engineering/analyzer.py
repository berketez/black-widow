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

import json
import logging
import re
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES
from karadul.reconstruction.c_algorithm_id import AlgorithmMatch, CAlgorithmResult
from karadul.reconstruction.engineering.constants import (
    ENGINEERING_CONSTANTS,
    HEX_LOOKUP,
    DECIMAL_PATTERNS,
    CONSTANT_GROUPS,
)
from karadul.reconstruction.engineering.patterns import ENGINEERING_PATTERNS
from karadul.reconstruction.engineering.apis import ENGINEERING_APIS, API_COMBINED_REGEX

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
    "kspsolve", "matassemblybegin", "snessolvе", "tssolvе",
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
    return _worker_analyzer._analyze_file(filepath, func_meta, has_domain)

# Noisy-OR birlestirmede ust sinir.  Asla %100 deme.
_NOISY_OR_CAP = 0.98

# Yuksek guven esigi: en az constant + API gerek.
_HIGH_CONFIDENCE_THRESHOLD = 0.70


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
        """Layer 1: IEEE-754 constant detection.

        HEX_LOOKUP ve DECIMAL_PATTERNS kullanarak sabit tespiti yapar.
        Ayni constant group'tan birden fazla sabit bulunursa
        confidence boost uygulanir.

        Ornek:
            Gauss 2-point sabitleri 0.577... ve -0.577... birlikte
            bulunursa -> "Gauss Quadrature 2pt" yuksek guvenle tespit edilir.
        """
        matches: list[AlgorithmMatch] = []

        # Hex tarama -- 0x ile baslayan sabitleri ara.
        # NOT: Bu metod sadece O(n) deterministik regex kullaniyor
        # (karakter sinifi [0-9a-f]+ ve string `in`). Backtracking riski yok,
        # buyuk body'lerde de guvenle calisir -- boyut siniri GEREKSIZ.
        # code icinde tek gecis: tum hex literal'leri topla.
        code_lower = code.lower()
        hex_literals = set(re.findall(r"0x[0-9a-f]+", code_lower))

        # Her hex literal'i HEX_LOOKUP'ta ara
        # hits: {(algo_name, category): (max_confidence, group, evidence_list)}
        hits: dict[tuple[str, str], tuple[float, str, list[str]]] = {}

        for hex_val in hex_literals:
            # hex_val: "0x3fe279a..." -> lookup key: "3fe279a..."
            lookup_key = hex_val[2:] if hex_val.startswith("0x") else hex_val
            entries = self._hex_lookup.get(lookup_key)
            if not entries:
                continue
            for ec in entries:
                key = (ec.algorithm, ec.category)
                if key not in hits:
                    hits[key] = (ec.confidence, ec.group, [f"hex: {hex_val} ({ec.description})"])
                else:
                    old_conf, old_group, old_ev = hits[key]
                    old_ev.append(f"hex: {hex_val} ({ec.description})")
                    new_conf = max(old_conf, ec.confidence)
                    hits[key] = (new_conf, old_group, old_ev)

        # Decimal tarama -- floating point sabitleri (0.577..., 3.14... vb.)
        for decimal_str, ec in self._decimal_patterns:
            if decimal_str in code:
                key = (ec.algorithm, ec.category)
                if key not in hits:
                    hits[key] = (ec.confidence, ec.group, [f"decimal: {decimal_str}"])
                else:
                    old_conf, old_group, old_ev = hits[key]
                    old_ev.append(f"decimal: {decimal_str}")
                    new_conf = max(old_conf, ec.confidence)
                    hits[key] = (new_conf, old_group, old_ev)

        # Group boosting: ayni group'tan birden fazla sabit bulunursa
        # confidence'i artir.
        group_counts: dict[str, int] = {}
        for (algo_name, category), (conf, group, evidence) in hits.items():
            if group:
                group_counts[group] = group_counts.get(group, 0) + len(evidence)

        for (algo_name, category), (conf, group, evidence) in hits.items():
            final_conf = conf
            # Group boost: ayni group'tan 2+ sabit bulunursa +0.15
            if group and group_counts.get(group, 0) >= 2:
                final_conf = min(0.90, final_conf + 0.15)
            # Birden fazla evidence: +0.05 per extra
            extra = max(0, len(evidence) - 1)
            if extra > 0:
                final_conf = min(0.90, final_conf + 0.05 * min(extra, 4))

            # Skip GROUP-ONLY constants that still have 0.0 confidence
            # (generic values like 0.5, 1.0, 2.0 that weren't boosted by group)
            if final_conf <= 0.0:
                continue

            matches.append(AlgorithmMatch(
                name=algo_name,
                category=category,
                confidence=round(final_conf, 3),
                detection_method="constant",
                evidence=evidence[:10],
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
        """Layer 2: Structural pattern detection.

        ENGINEERING_PATTERNS'deki regex pattern'lerini kod icinde arar.
        Her pattern icin min_matches esigi vardir.

        ONEMLI: Structural-only tespit _STRUCTURAL_ONLY_CAP (0.50)
        ile sinirlanir.  Yuksek guven icin constant veya API kaniti gerekir.

        Optimizasyon: Her pattern icin anchor keyword pre-filter uygular.
        Anchor keyword'lerden en az biri kodda yoksa regex'i calistirmaz.
        468 pattern icin ortalama %85+ atlama orani saglar.
        """
        matches: list[AlgorithmMatch] = []

        # v1.8.0: ENGINEERING_PATTERNS .* ve .+ icermiyor, tum pattern'ler
        # [^...] negated char class + \w + \s gibi O(n) safe yapilarda.
        # Anchor pre-filter ile %85+ atlama orani zaten saglanir.
        # Boyut siniri kaldirildi -- hicbir fonksiyon atlanmaz.

        code_lower = code.lower()

        for idx, sp in enumerate(self._structural_patterns):
            # Pre-filter: Her regex icin anchor set var.
            # Pattern calistirilmali eger herhangi bir regex'in anchor
            # kosuluunu sagliyorsa (anchor bos = her zaman calistir,
            # anchor dolu = en az biri kodda olmali).
            per_regex_anchors = self._structural_anchors[idx]
            should_run = False
            for regex_anchors in per_regex_anchors:
                if not regex_anchors:
                    # Bu regex'in anchor'u yok -> genel pattern, calistir
                    should_run = True
                    break
                if any(a in code_lower for a in regex_anchors):
                    should_run = True
                    break
            if not should_run:
                continue

            total_hits = 0
            evidence: list[str] = []

            for regex in sp.patterns:
                found = regex.findall(code)
                if found:
                    total_hits += len(found)
                    sample = found[0] if isinstance(found[0], str) else str(found[0])
                    evidence.append(
                        f"{sp.name}: matched '{sample[:80]}'"
                    )

            if total_hits >= sp.min_matches and evidence:
                # Base confidence from pattern definition
                base_conf = sp.confidence
                # Bonus per extra hit beyond minimum
                bonus = min(0.20, 0.03 * (total_hits - sp.min_matches))
                conf = base_conf + bonus

                # Structural-only cap
                conf = min(conf, _STRUCTURAL_ONLY_CAP)

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
                combined.append(group[0])
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
        """Check if the binary contains scientific/engineering domain indicators.

        Scans function names from metadata AND a quick skim of a few C files
        for imports/symbols matching known scientific libraries.

        Returns True if ANY domain indicator is found, meaning we should run
        the full 3-layer analysis.  Returns False if the binary appears to be
        non-scientific (e.g. a text editor, game, etc.), in which case only
        API detection should run.
        """
        # 1. Check function names in metadata
        if func_meta:
            func_names_lower = {name.lower() for name in func_meta.keys()}
            for indicator in _ALL_DOMAIN_INDICATORS:
                # Check both exact match and substring
                if indicator in func_names_lower:
                    logger.debug("Domain indicator found in func_meta: %s", indicator)
                    return True
                # Also check if any function name CONTAINS the indicator
                for fn in func_names_lower:
                    if indicator in fn:
                        logger.debug(
                            "Domain indicator '%s' found in function '%s'",
                            indicator, fn,
                        )
                        return True

        # 2. Quick skim: read first ~50KB of up to 10 C files for library calls
        sample_files = c_files[:10]
        for f in sample_files:
            try:
                # Read only first 50KB for speed
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read(50_000).lower()
                for indicator in _ALL_DOMAIN_INDICATORS:
                    if indicator in text:
                        logger.debug(
                            "Domain indicator '%s' found in %s",
                            indicator, f.name,
                        )
                        return True
            except OSError:
                continue

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
