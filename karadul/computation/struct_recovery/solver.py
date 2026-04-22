"""StructLayoutSolver — MaxSMT encoding + Z3 cozum + decode.

Akis:
    1. AliasingAnalyzer girdi var/must_alias/type_hints'ten class'lari kurar.
    2. CandidateSynthesizer access pattern'lerinden aday struct'lar uretir.
    3. encoder.encode MaxSMT problemini Z3 Optimize'a yukler.
    4. opt.check() ile cozer (timeout'lu).
    5. Model decode edilir -> RecoveredStructLayout.

CPU-ONLY. Z3 tek cekirdekte ms-dusuk saniyede tipik problemi cozer.
Feature flag default FALSE (ComputationConfig.enable_computation_struct_recovery).

Graceful behavior:
    - Z3 yoksa: RuntimeError (encoder'dan). Feature flag kontrolu cagiranda.
    - Bos input: bos RecoveredStructLayout.
    - Timeout: Z3 partial model verirse decode et; yoksa tum erisimler unknown.
    - unsat: teorik olarak H4 ile mumkun (celisen tipler) — tum unknown ile dur.
"""

from __future__ import annotations

import logging
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass
from typing import Any, Optional

try:
    import z3
    _Z3_AVAILABLE = True
except ImportError:  # pragma: no cover
    _Z3_AVAILABLE = False
    z3 = None  # type: ignore

logger = logging.getLogger(__name__)

# v1.10.0 Batch 6D (FIX 5 full): ProcessPool worker sayisi sert cap'i.
# Z3 context'leri RAM-heavy (her worker 50-150 MB); 10+ worker diminishing
# returns veriyor ve macOS/Linux spawn context maliyetini patlatiyor.
_MAX_PARALLEL_WORKERS = 10

# Break-even component sayisi: spawn overhead ~200-400ms oldugu icin tek
# component varsa sequential her zaman hizli. 2 component kucuk problem
# icin hala sequential kazanir. 3+ component'ten sonra ProcessPool
# spawn'i amortize ediyor. Testler bu esikle davranisi dogrular.
_PARALLEL_MIN_COMPONENTS = 2

# v1.10.0 Batch 5B MED-14: Z3 input size hard cap.
# SecurityConfig.max_z3_access_count ile esit; modul-seviyesi override icin
# test'ler ``solver._MAX_Z3_ACCESSES = 100`` yapabilir.
_MAX_Z3_ACCESSES = 10_000

# v1.10.0 Batch 6A (Codex audit): Per-component variable cap.
# Tek alias component'inda >500 variable oldugunda MaxSMT O(V^2 * K * J)
# soft constraint olusur (V=variable, K=aday, J=alan). 500+ variable
# component'i bulunursa uyari + rejection. Pratik RE workload'larinda
# alias component'lari 10-100 variable'dan olusur; 500+ genelde SSA
# over-unification isareti.
_MAX_COMPONENT_VARIABLES = 500

from karadul.computation.config import ComputationConfig
from karadul.computation.struct_recovery.aliasing import AliasingAnalyzer
from karadul.computation.struct_recovery.candidate_synthesizer import (
    CandidateSynthesizer,
    collect_accesses_per_family,
)
from karadul.computation.struct_recovery.encoder import encode, ensure_z3_available
from karadul.computation.struct_recovery.types import (
    AliasClass,
    MemoryAccess,
    RecoveredStructLayout,
    StructCandidate,
)


# ---------------------------------------------------------------------------
# v1.10.0 Batch 6D (FIX 5 full): Paralel solve destek veri tipleri.
# ---------------------------------------------------------------------------

@dataclass
class ComponentResult:
    """Bir component'in paralel solve ciktisi.

    Worker process'ten ana process'e pickle edilerek gecer; sadece
    pickle-safe alanlar tutulur (Z3 nesneleri DOKUNULMAZ — worker
    decode'u bitirmis olmali).

    Attributes:
        component_id: Component indeksi (debug icin).
        layout: RecoveredStructLayout; worker decode ettikten sonra.
            Hata/timeout durumunda tum class'larin unknown_accesses'i ile
            confidence=0.0 RecoveredStructLayout.
        status: "ok" | "timeout" | "error" | "skipped_oversized".
        error_msg: status != "ok" ise kisa mesaj.
    """
    component_id: int
    layout: RecoveredStructLayout
    status: str = "ok"
    error_msg: str = ""


def _solve_component_in_worker(
    component_id: int,
    accesses: list[MemoryAccess],
    classes: list[AliasClass],
    candidates_by_family: dict[str, list[StructCandidate]],
    config: ComputationConfig,
    component_timeout_s: float,
) -> ComponentResult:
    """Worker process ana fonksiyonu.

    v1.10.0 Batch 6D: Her worker kendi PROCESS'inde calisir ve ``spawn``
    multiprocessing context'i sayesinde her worker'da Z3 de sifirdan
    import edilir. Python process seviyesindeki izolasyon Z3'un thread-local
    default context'ini zaten process-local yaptigi icin ek
    ``z3.Context()`` nesnesi YARATMAYIZ — encoder z3.Bool/Not/PbEq'i default
    context uzerinden cagiriyor, ayri context nesnesi kullansak context-
    mismatch hatalari olusur.

    Her worker kendi Z3 default context'i ile calisir (spawn process
    izolasyonu); bu cross-worker state paylasmasini GARANTI EDER.

    Args:
        component_id: Geriye raporlanacak component no.
        accesses/classes/candidates_by_family/config: Solver girdisi
            (tamami pickle-safe dataclass).
        component_timeout_s: Bu component icin Z3 timeout.

    Returns:
        ComponentResult. Hata/timeout durumunda status != "ok".
    """
    try:
        import z3 as _z3  # worker-local import (spawn sonrasi fresh)
    except ImportError as exc:  # pragma: no cover
        empty = RecoveredStructLayout(
            classes=list(classes),
            assigned_structs={},
            unknown_accesses=list(accesses),
            confidence=0.0,
            solver_time_seconds=0.0,
        )
        return ComponentResult(
            component_id=component_id,
            layout=empty,
            status="error",
            error_msg=f"z3 import failure in worker: {exc}",
        )

    # Worker kendi process'inde cakisacak z3 default context kullaniyor.
    # Encoder z3.Bool/Not/PbEq'i default context'e gore kurdugu icin
    # optimize'i de default context'ten yaratmak sart.
    optimize = _z3.Optimize()

    # Access'leri class'a grupla (encoder girdi formati).
    analyzer = AliasingAnalyzer()
    class_to_accesses = analyzer.group_accesses_by_class(
        classes, [a.var_name for a in accesses],
    )

    start = time.perf_counter()
    try:
        problem = encode(
            accesses=accesses,
            classes=classes,
            class_to_accesses=class_to_accesses,
            candidates_by_family=candidates_by_family,
            config=config,
            opt=optimize,
        )
        # Z3 icsel timeout (ms).
        timeout_ms = int(max(1, component_timeout_s * 1000))
        problem.optimize.set("timeout", timeout_ms)
        check_result = problem.optimize.check()
        elapsed = time.perf_counter() - start

        # Decode — solver._decode mantigi ama worker-local.
        model = None
        if check_result in (_z3.sat, _z3.unknown):
            try:
                model = problem.optimize.model()
            except _z3.Z3Exception:
                model = None

        if model is None:
            layout = RecoveredStructLayout(
                classes=list(classes),
                assigned_structs={},
                unknown_accesses=list(accesses),
                confidence=0.0,
                solver_time_seconds=elapsed,
            )
            status = "timeout" if check_result == _z3.unknown else "ok"
            return ComponentResult(
                component_id=component_id, layout=layout, status=status,
            )

        assigned: dict[str, StructCandidate] = {}
        seen_family: set[str] = set()
        for ci, cls in enumerate(classes):
            if cls.type_family in seen_family:
                continue
            cand_idxs = problem.candidates_for_family.get(cls.type_family, [])
            for k in cand_idxs:
                var = problem.type_vars.get((ci, k))
                if var is None:
                    continue
                val = model.eval(var, model_completion=True)
                if _z3.is_true(val):
                    assigned[cls.type_family] = problem.all_candidates[k]
                    seen_family.add(cls.type_family)
                    break

        unknown_accesses: list[MemoryAccess] = []
        explained = 0
        for ai, acc in enumerate(accesses):
            uvar = problem.unknown_vars.get(ai)
            if uvar is None:
                unknown_accesses.append(acc)
                continue
            uval = model.eval(uvar, model_completion=True)
            if _z3.is_true(uval):
                unknown_accesses.append(acc)
            else:
                explained += 1

        total = len(accesses)
        confidence = (explained / total) if total else 1.0
        layout = RecoveredStructLayout(
            classes=list(classes),
            assigned_structs=assigned,
            unknown_accesses=unknown_accesses,
            confidence=confidence,
            solver_time_seconds=elapsed,
        )
        return ComponentResult(
            component_id=component_id, layout=layout, status="ok",
        )
    except Exception as exc:  # pragma: no cover
        elapsed = time.perf_counter() - start
        empty = RecoveredStructLayout(
            classes=list(classes),
            assigned_structs={},
            unknown_accesses=list(accesses),
            confidence=0.0,
            solver_time_seconds=elapsed,
        )
        return ComponentResult(
            component_id=component_id,
            layout=empty,
            status="error",
            error_msg=f"{type(exc).__name__}: {exc}",
        )


class StructLayoutSolver:
    """MaxSMT-based struct layout kurtarici (Z3, CPU-only).

    v1.10.0 H1 (perf fix): ``self._optimize`` tek sefer yaratilir,
    her ``solve()`` cagrisi ``push()/pop()`` cercevesinde calisir.
    Bu Z3 init overhead'ini (~50-200 ms/call) ortadan kaldirir.
    Z3 import edilememise (``_Z3_AVAILABLE=False``) None kalir; solver
    kullanilmaya calisinca ``ensure_z3_available()`` hata atar.
    """

    def __init__(self, config: Optional[ComputationConfig] = None) -> None:
        self.config = config or ComputationConfig()
        # v1.10.0 H1: Kalici Z3 Optimize nesnesi. Z3 yoksa None; ilk
        # ``solve()`` cagrisinda ``ensure_z3_available()`` hata firlatir.
        self._optimize: Any = z3.Optimize() if _Z3_AVAILABLE else None

    # ------------------------------------------------------------------
    # Ust duzey API — caller muhtemelen bunu kullanir.
    # ------------------------------------------------------------------
    def solve_from_raw(
        self,
        accesses: list[MemoryAccess],
        variables: Optional[list[str]] = None,
        must_alias: Optional[list[tuple[str, str]]] = None,
        type_hints: Optional[dict[str, str]] = None,
        candidates: Optional[list[StructCandidate]] = None,
        max_time_seconds: Optional[float] = None,
    ) -> RecoveredStructLayout:
        """Ham girdiden tam pipeline: aliasing -> candidates -> MaxSMT.

        Feature flag kapaliysa bos layout doner.
        """
        if not self.config.enable_computation_struct_recovery:
            return self._empty_result(0.0)
        if not accesses:
            return self._empty_result(0.0)

        variables = variables or sorted({a.var_name for a in accesses})
        must_alias = must_alias or []
        type_hints = type_hints or {}

        analyzer = AliasingAnalyzer()
        classes = analyzer.build_classes(variables, must_alias, type_hints)

        if candidates is None:
            synthesizer = CandidateSynthesizer(self.config)
            var_to_family = {
                v: c.type_family for c in classes for v in c.variables
            }
            per_family = collect_accesses_per_family(accesses, var_to_family)
            candidates_by_family = synthesizer.synthesize_per_family(per_family)
        else:
            # Manuel aday havuzu — tum ailelere ayni liste verilir.
            candidates_by_family = {
                c.type_family: list(candidates) for c in classes
            }

        return self.solve(
            accesses=accesses,
            classes=classes,
            candidates_by_family=candidates_by_family,
            max_time_seconds=max_time_seconds,
        )

    def solve(
        self,
        accesses: list[MemoryAccess],
        classes: list[AliasClass],
        candidates_by_family: Optional[dict[str, list[StructCandidate]]] = None,
        candidates: Optional[list[StructCandidate]] = None,
        max_time_seconds: Optional[float] = None,
    ) -> RecoveredStructLayout:
        """MaxSMT cozucuyu calistir, layout dondur.

        Args:
            accesses: Tum bellek erisimleri.
            classes: Alias class listesi (AliasingAnalyzer.build_classes'tan).
            candidates_by_family: family -> aday listesi. None ise
                ``candidates`` argumani tum ailelere uygulanir.
            candidates: Basit/tek-aile durumu icin duz liste.
            max_time_seconds: Bu cagri icin timeout. None -> config.

        Returns:
            RecoveredStructLayout.
        """
        if not self.config.enable_computation_struct_recovery:
            return self._empty_result(0.0)

        if not accesses or not classes:
            return RecoveredStructLayout(
                classes=list(classes),
                assigned_structs={},
                unknown_accesses=list(accesses),
                confidence=0.0 if accesses else 1.0,
                solver_time_seconds=0.0,
            )

        # v1.10.0 Batch 5B MED-14: Z3 exponential DoS koruma.
        # MaxSMT over N accesses ~ O(2^N) en kotu durumda; N>10K genelde
        # interaktif binary'de gercekci degil, ama malicious input uzerinde
        # test ederken Z3 saatlerce takilabilir. Hard cap uyguluyoruz.
        # SecurityConfig'ten gelirdi ama bu modulun Config erisimi yok;
        # _MAX_Z3_ACCESSES modul-seviyesi sabit, test-friendly.
        if len(accesses) > _MAX_Z3_ACCESSES:
            logger.warning(
                "Z3 MaxSMT: access count %d > cap %d, reddedildi (DoS koruma)",
                len(accesses), _MAX_Z3_ACCESSES,
            )
            return RecoveredStructLayout(
                classes=list(classes),
                assigned_structs={},
                unknown_accesses=list(accesses),
                confidence=0.0,
                solver_time_seconds=0.0,
            )

        # v1.10.0 Batch 6A (Codex audit): Per-component variable cap.
        # Her alias class tek bir component; >MAX_COMPONENT_VARIABLES uyesi
        # olan component bulunursa MaxSMT quadratic patlar. O component'e
        # ait erisimleri unknown'a at ve devam et (diger component'ler
        # etkilenmeden cozulur).
        #
        # v1.11 hedefi (FIX 5 tam implement): Union-find ile component-per-
        # component ayri Z3 Optimize + ProcessPoolExecutor paralel solve.
        # Bu surumde pragmatik: pipeline step zaten per-function cagiriyor
        # (her fonksiyon kendi scope'unda); sadece tek fonksiyon icinde
        # dejenere component'leri reddetmek yeter.
        oversized = [c for c in classes if len(c.variables) > _MAX_COMPONENT_VARIABLES]
        if oversized:
            logger.warning(
                "Z3 MaxSMT: %d alias component variable cap'i (%d) asti, "
                "bu component'ler atlandi.",
                len(oversized), _MAX_COMPONENT_VARIABLES,
            )
            # Dejenere component'lerdeki variable'lara ait erisimleri
            # unknown_accesses'a koy.
            oversized_vars: set[str] = set()
            for cls in oversized:
                oversized_vars.update(cls.variables)
            filtered_classes = [
                c for c in classes if c not in oversized
            ]
            filtered_accesses = [
                a for a in accesses if a.var_name not in oversized_vars
            ]
            skipped_accesses = [
                a for a in accesses if a.var_name in oversized_vars
            ]
            if not filtered_classes or not filtered_accesses:
                return RecoveredStructLayout(
                    classes=list(classes),
                    assigned_structs={},
                    unknown_accesses=list(accesses),
                    confidence=0.0,
                    solver_time_seconds=0.0,
                )
            # Recurse with filtered input; skipped'leri unknown'a eklemek
            # icin sonrasinda unknown_accesses listesine merge et.
            sub_result = self.solve(
                accesses=filtered_accesses,
                classes=filtered_classes,
                candidates_by_family=candidates_by_family,
                candidates=candidates,
                max_time_seconds=max_time_seconds,
            )
            merged_unknown = list(sub_result.unknown_accesses) + skipped_accesses
            total_accesses = len(accesses)
            explained = total_accesses - len(merged_unknown)
            return RecoveredStructLayout(
                classes=list(classes),
                assigned_structs=sub_result.assigned_structs,
                unknown_accesses=merged_unknown,
                confidence=(explained / total_accesses) if total_accesses else 0.0,
                solver_time_seconds=sub_result.solver_time_seconds,
            )

        # Aday haritasi.
        if candidates_by_family is None:
            candidates_by_family = {
                c.type_family: list(candidates or []) for c in classes
            }

        # Aile -> aday yoksa, o aileye ait erisimler zorunlu unknown.
        has_any_cand = any(
            len(v) > 0 for v in candidates_by_family.values()
        )
        if not has_any_cand:
            return RecoveredStructLayout(
                classes=list(classes),
                assigned_structs={},
                unknown_accesses=list(accesses),
                confidence=0.0,
                solver_time_seconds=0.0,
            )

        # Class -> erisim indeksleri.
        analyzer = AliasingAnalyzer()
        class_to_accesses = analyzer.group_accesses_by_class(
            classes, [a.var_name for a in accesses],
        )

        ensure_z3_available()
        # v1.10.0 H1: Kalici Optimize nesnesini push/pop ile kullan.
        # Eski davranis (yeni Optimize her solve'da) ~50-200 ms init cezasi
        # yaratiyordu; push/pop ile Z3 context tek sefer init ediliyor.
        # Safety: ilk instance (H1 init edildiyse) self._optimize set'tir.
        # Fallback: None ise (eski testing path veya Z3 gec yuklendi) yeni yarat.
        if self._optimize is None:
            self._optimize = z3.Optimize()
        self._optimize.push()
        try:
            problem = encode(
                accesses=accesses,
                classes=classes,
                class_to_accesses=class_to_accesses,
                candidates_by_family=candidates_by_family,
                config=self.config,
                opt=self._optimize,
            )

            timeout = max_time_seconds or self.config.struct_solver_timeout
            problem.optimize.set("timeout", int(max(1, timeout * 1000)))

            start = time.perf_counter()
            result = problem.optimize.check()
            elapsed = time.perf_counter() - start

            return self._decode(problem, accesses, classes, result, elapsed)
        finally:
            # Pop HEP yapilmali -- exception olsa bile persistent Optimize
            # state'ini bozmayalim. Eger pop patlarsa (teorik: Z3 bug)
            # en azindan Optimize'i yeniden yarat.
            try:
                self._optimize.pop()
            except Exception:  # pragma: no cover
                self._optimize = z3.Optimize() if _Z3_AVAILABLE else None

    # ------------------------------------------------------------------
    # Decode
    # ------------------------------------------------------------------
    def _decode(
        self,
        problem,
        accesses: list[MemoryAccess],
        classes: list[AliasClass],
        check_result,
        elapsed: float,
    ) -> RecoveredStructLayout:
        """Z3 sonucundan RecoveredStructLayout'u kur."""
        # sat veya unknown (timeout'ta partial model) durumunda model dener.
        model = None
        if check_result in (z3.sat, z3.unknown):
            try:
                model = problem.optimize.model()
            except z3.Z3Exception:
                model = None

        if model is None:
            # Cozum yok — hepsi unknown.
            return RecoveredStructLayout(
                classes=list(classes),
                assigned_structs={},
                unknown_accesses=list(accesses),
                confidence=0.0,
                solver_time_seconds=elapsed,
            )

        # Ailelere atanan aday.
        assigned: dict[str, StructCandidate] = {}
        seen_family: set[str] = set()
        for ci, cls in enumerate(classes):
            if cls.type_family in seen_family:
                continue
            cand_idxs = problem.candidates_for_family.get(cls.type_family, [])
            for k in cand_idxs:
                var = problem.type_vars.get((ci, k))
                if var is None:
                    continue
                val = model.eval(var, model_completion=True)
                if z3.is_true(val):
                    assigned[cls.type_family] = problem.all_candidates[k]
                    seen_family.add(cls.type_family)
                    break

        # Unknown erisimleri listele.
        unknown_accesses: list[MemoryAccess] = []
        explained = 0
        for ai, acc in enumerate(accesses):
            uvar = problem.unknown_vars.get(ai)
            if uvar is None:
                # Teorik olarak olmamali ama savunma.
                unknown_accesses.append(acc)
                continue
            uval = model.eval(uvar, model_completion=True)
            if z3.is_true(uval):
                unknown_accesses.append(acc)
            else:
                explained += 1

        total = len(accesses)
        confidence = (explained / total) if total else 1.0

        return RecoveredStructLayout(
            classes=list(classes),
            assigned_structs=assigned,
            unknown_accesses=unknown_accesses,
            confidence=confidence,
            solver_time_seconds=elapsed,
        )

    # ------------------------------------------------------------------
    def _empty_result(self, elapsed: float) -> RecoveredStructLayout:
        return RecoveredStructLayout(
            classes=[],
            assigned_structs={},
            unknown_accesses=[],
            confidence=1.0,
            solver_time_seconds=elapsed,
        )

    # ------------------------------------------------------------------
    # v1.10.0 Batch 6D (FIX 5 full): Per-component paralel solve.
    # ------------------------------------------------------------------
    def solve_parallel(
        self,
        accesses: list[MemoryAccess],
        variables: Optional[list[str]] = None,
        must_alias: Optional[list[tuple[str, str]]] = None,
        type_hints: Optional[dict[str, str]] = None,
        max_time_seconds: Optional[float] = None,
    ) -> RecoveredStructLayout:
        """Ham girdiyi component'lere boler ve paralel cozer.

        v1.10.0 Batch 6D:
            - AliasingAnalyzer ile class'lar kurulur.
            - ``find_connected_components`` ile disjoint solve unit'leri
              cikarilir.
            - ``_MAX_COMPONENT_VARIABLES`` (500) ustu component'ler skip
              (unknown'a atilir — eski sequential davranis ayni).
            - Geri kalan component'ler ``ProcessPoolExecutor`` + ``spawn``
              ile paralel cozulur. Her worker kendi ``z3.Context()``.
            - Tek component veya ``enable_parallel_solve=False`` -> eski
              sequential ``solve_from_raw`` fallback.
            - Tum component sonuclari ``_merge_component_results`` ile
              tek RecoveredStructLayout'a birlestirilir.

        Feature flag kapaliysa bos layout doner (solve_from_raw ile ayni).
        """
        if not self.config.enable_computation_struct_recovery:
            return self._empty_result(0.0)
        if not accesses:
            return self._empty_result(0.0)

        # Fallback: paralel kapali -> sequential.
        if not self.config.enable_parallel_solve:
            return self.solve_from_raw(
                accesses=accesses,
                variables=variables,
                must_alias=must_alias,
                type_hints=type_hints,
                max_time_seconds=max_time_seconds,
            )

        variables = variables or sorted({a.var_name for a in accesses})
        must_alias = must_alias or []
        type_hints = type_hints or {}

        analyzer = AliasingAnalyzer()
        classes = analyzer.build_classes(variables, must_alias, type_hints)
        if not classes:
            return self._empty_result(0.0)

        components = analyzer.find_connected_components(classes)
        per_comp_classes, per_comp_accesses, orphan_accesses = (
            analyzer.partition_accesses_by_component(
                classes, components, accesses,
            )
        )

        # Oversized component'leri ayikla.
        safe_indices: list[int] = []
        skipped_accesses: list[MemoryAccess] = []
        skipped_classes: list[AliasClass] = []
        for idx, comp_classes in enumerate(per_comp_classes):
            total_vars = sum(len(c.variables) for c in comp_classes)
            if total_vars > _MAX_COMPONENT_VARIABLES:
                logger.warning(
                    "Component %d: %d variable cap'i (%d) asti, atlandi.",
                    idx, total_vars, _MAX_COMPONENT_VARIABLES,
                )
                skipped_accesses.extend(per_comp_accesses[idx])
                skipped_classes.extend(comp_classes)
            else:
                safe_indices.append(idx)

        # Tek safe component -> sequential (spawn overhead amortize olmaz).
        if len(safe_indices) < _PARALLEL_MIN_COMPONENTS:
            return self.solve_from_raw(
                accesses=accesses,
                variables=variables,
                must_alias=must_alias,
                type_hints=type_hints,
                max_time_seconds=max_time_seconds,
            )

        # Her safe component icin candidate synthesize et.
        synthesizer = CandidateSynthesizer(self.config)
        per_comp_candidates: dict[int, dict[str, list[StructCandidate]]] = {}
        for idx in safe_indices:
            comp_classes = per_comp_classes[idx]
            comp_accesses = per_comp_accesses[idx]
            var_to_family = {
                v: c.type_family for c in comp_classes for v in c.variables
            }
            per_family = collect_accesses_per_family(comp_accesses, var_to_family)
            per_comp_candidates[idx] = synthesizer.synthesize_per_family(per_family)

        # Worker ayarlari.
        max_workers = self.config.max_parallel_workers or None
        if max_workers is None:
            try:
                from karadul.config import CPU_PERF_CORES
                max_workers = CPU_PERF_CORES
            except ImportError:  # pragma: no cover
                max_workers = 2
        max_workers = max(1, min(max_workers, _MAX_PARALLEL_WORKERS))

        component_timeout = max_time_seconds or self.config.component_timeout_s

        # spawn context — macOS fork-safety.
        mp_ctx = multiprocessing.get_context("spawn")

        # Paralel solve.
        start = time.perf_counter()
        component_results: list[ComponentResult] = []
        try:
            with ProcessPoolExecutor(
                max_workers=max_workers,
                mp_context=mp_ctx,
            ) as executor:
                future_to_idx = {
                    executor.submit(
                        _solve_component_in_worker,
                        idx,
                        per_comp_accesses[idx],
                        per_comp_classes[idx],
                        per_comp_candidates[idx],
                        self.config,
                        component_timeout,
                    ): idx
                    for idx in safe_indices
                }
                # Her future icin wall-clock timeout (Z3 icsel timeout'tan
                # %50 fazla + spawn overhead icin 2s pay).
                wall_timeout = component_timeout * 1.5 + 2.0
                for future in list(future_to_idx.keys()):
                    idx = future_to_idx[future]
                    try:
                        res = future.result(timeout=wall_timeout)
                        component_results.append(res)
                    except FuturesTimeout:
                        logger.warning(
                            "Component %d wall-clock timeout; unknown'a atiliyor.",
                            idx,
                        )
                        empty = RecoveredStructLayout(
                            classes=list(per_comp_classes[idx]),
                            assigned_structs={},
                            unknown_accesses=list(per_comp_accesses[idx]),
                            confidence=0.0,
                            solver_time_seconds=component_timeout,
                        )
                        component_results.append(ComponentResult(
                            component_id=idx, layout=empty,
                            status="timeout", error_msg="wall-clock timeout",
                        ))
                        # future cancel etmeyi dene (Python 3.9+ pool da kapaninca
                        # context manager exit'te zaten cleanup yapar).
                        future.cancel()
                    except Exception as exc:  # pragma: no cover
                        logger.warning(
                            "Component %d hata: %s (unknown'a atiliyor)",
                            idx, exc,
                        )
                        empty = RecoveredStructLayout(
                            classes=list(per_comp_classes[idx]),
                            assigned_structs={},
                            unknown_accesses=list(per_comp_accesses[idx]),
                            confidence=0.0,
                            solver_time_seconds=0.0,
                        )
                        component_results.append(ComponentResult(
                            component_id=idx, layout=empty,
                            status="error", error_msg=str(exc),
                        ))
        except Exception as exc:  # pragma: no cover
            # ProcessPool kurulum/crash: toplam fallback sequential.
            logger.warning(
                "ProcessPool paralel solve crash, sequential fallback: %s",
                exc,
            )
            return self.solve_from_raw(
                accesses=accesses,
                variables=variables,
                must_alias=must_alias,
                type_hints=type_hints,
                max_time_seconds=max_time_seconds,
            )

        wall_elapsed = time.perf_counter() - start
        return self._merge_component_results(
            classes=classes,
            all_accesses=accesses,
            component_results=component_results,
            skipped_accesses=skipped_accesses,
            skipped_classes=skipped_classes,
            orphan_accesses=orphan_accesses,
            wall_elapsed=wall_elapsed,
        )

    def _merge_component_results(
        self,
        classes: list[AliasClass],
        all_accesses: list[MemoryAccess],
        component_results: list[ComponentResult],
        skipped_accesses: list[MemoryAccess],
        skipped_classes: list[AliasClass],
        orphan_accesses: list[MemoryAccess],
        wall_elapsed: float,
    ) -> RecoveredStructLayout:
        """Component result'lari tek RecoveredStructLayout'a merge et."""
        merged_assigned: dict[str, StructCandidate] = {}
        merged_unknown: list[MemoryAccess] = []
        total_solver_time = 0.0

        for res in component_results:
            layout = res.layout
            # Family cakismasi teorik olarak mumkun degil (components
            # family'ye gore kesilmis), ama defansif: ilk gelen kazanir.
            for fam, cand in layout.assigned_structs.items():
                merged_assigned.setdefault(fam, cand)
            merged_unknown.extend(layout.unknown_accesses)
            total_solver_time += layout.solver_time_seconds

        # Oversized skipped + orphan -> zorunlu unknown.
        merged_unknown.extend(skipped_accesses)
        merged_unknown.extend(orphan_accesses)

        total = len(all_accesses)
        explained = total - len(merged_unknown)
        explained = max(0, min(explained, total))
        confidence = (explained / total) if total else 1.0

        # solver_time: paralel wall-clock, toplam CPU time bilgi icin logla.
        logger.debug(
            "Paralel solve: %d component, wall=%.3fs, CPU toplam=%.3fs",
            len(component_results), wall_elapsed, total_solver_time,
        )
        return RecoveredStructLayout(
            classes=list(classes),
            assigned_structs=merged_assigned,
            unknown_accesses=merged_unknown,
            confidence=confidence,
            solver_time_seconds=wall_elapsed,
        )
