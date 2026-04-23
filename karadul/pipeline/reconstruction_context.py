"""ReconstructionStage state container — v1.12.0 stages.py split altyapisi.

Bu modul ``stages.py`` icindeki ``ReconstructionStage._execute_binary``
fonksiyonunun (su an 3173 satir, ~40+ lokal degisken) split edilmesi icin
gerekli **explicit state container**'ini tanimlar.

Iliskili plan: ``docs/migrations/stages_split_plan.md`` (v1.12.0).

**Faz durumu:**

- Faz 1 (v1.12.0-alpha1, ``v1.11.x`` uzerinde): Bu dosya olusturulur. Dataclass
  tanimlidir, ``stages.py`` icinde **henuz kullanilmaz**. Amac: altyapi hazir
  olsun, ikinci developer parity testi yazabilsin.
- Faz 2 (v1.12.0-alpha1 devami): ``_execute_binary`` icindeki 40+ lokal
  degisken bu dataclass'a tasinir. 18 alt metot eklenir.
- Faz 3+ (v1.12.0-alpha2/beta): Dead code temizligi, feedback loop step
  registry'ye tasinma.

**Kritik tasarim kurallari:**

1. Dataclass **pickle edilemez** — icinde engine instance'lari (QW4
   pre-instantiation: ``pre_comp_engine``, ``pre_c_namer``, ``pre_type_rec``)
   tutuluyor. Multi-process kullanim yasak.
2. ``artifacts``, ``stats``, ``errors`` alanlarinin anlami ``StageResult`` ile
   ayni — Faz 2'de dogrudan ``StageResult`` insa etmek icin kullanilacak.
3. Tum mutation noktasi `rc.X = ...` seklinde olmali (grep'lenebilirlik).
4. Yeni alan eklerken plan dokumanini da guncelle.

**Plan referansi (stages_split_plan.md §4):** ``_ReconCtx`` ve
``_ReconLoopState`` iki dataclass olarak tasarlandi. Loop state ayri
tutuldu cunku feedback loop iterasyonlari arasinda **loop-level** state
(ornek: ``prev_named_set``, ``loop_decompiled_dir``) ve **iter-local** state
(ornek: ``computation_result``, ``naming_result``) karisiyordu.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # StageResult tipi yalnizca annotation icin gerekli, runtime import
    # cycle'ini onlemek icin TYPE_CHECKING altinda.
    from karadul.stages import StageResult


@dataclass
class ReconLoopState:
    """Feedback loop icin loop-level + iter-local state.

    ``_execute_binary`` satir 2110-3397 arasindaki feedback loop (``v1.7.5``
    iteratif computation -> c_naming -> name_merger -> type_recovery)
    state'ini tasir. Plan ``stages_split_plan.md`` §4.
    """

    # Loop-level konfigurasyon
    max_iterations: int = 5
    iter_idx: int = 0

    # Convergence kontrolu (v1.7.5 loop invariant)
    prev_named_set: set[str] = field(default_factory=set)
    iteration_stats: list[dict[str, Any]] = field(default_factory=list)

    # Iterasyonlar arasi degisen decompiled dizin
    loop_decompiled_dir: Path | None = None

    # Kesfedilmis cagri grafigi komsuluklari (stages.py iceki helper cache)
    cg_neighbors: dict[str, set[str]] = field(default_factory=dict)

    # C dosya path cache'i (Phase 1'de doldurulur, iterasyonlar sirasinda
    # guncellenir, Phase 3'te de kullanilir — bkz. InlineDetector).
    cfile_by_name: dict[str, Path] = field(default_factory=dict)

    # Incremental file set — type recovery sadece degisenleri re-process eder.
    incremental_files: list[Path] | None = None

    # rglob cache'leri (performans: her iter'de rglob cagirma)
    rglob_c_files: list[Path] = field(default_factory=list)
    rglob_cfile_map: dict[str, Path] = field(default_factory=dict)
    rglob_cached_dir: Path | None = None

    # Pre-instantiated modules (QW4 optimization — her iter'de yeniden
    # insa etmemek icin bir kere create edilip reuse edilirler).
    pre_comp_engine: Any = None
    pre_c_namer: Any = None
    pre_type_rec: Any = None

    # Iter-local sonuclar — her iterasyon basinda uzerine yazilir.
    computation_result: Any = None
    naming_result: Any = None
    bindiff_matches: dict[str, Any] = field(default_factory=dict)
    refdiff_matches: dict[str, Any] = field(default_factory=dict)
    merged_names: dict[str, Any] = field(default_factory=dict)
    type_rec_result: Any = None

    # Convergence flag — ``_feedback_iter_type_recovery`` true dondururse
    # ``_execute_binary`` loop'tan cikar.
    converged: bool = False


@dataclass
class ReconstructionContext:
    """``ReconstructionStage._execute_binary`` icin explicit state container.

    Plan ``stages_split_plan.md`` §4 — 3173 satirlik fonksiyonun 18 alt
    metota ayristirilmasi sirasinda 40+ lokal degiskeni topluca tasiyacak
    dataclass.

    **Kullanim ornegi (Faz 2'de):**

    .. code-block:: python

        def _execute_binary(self, context: PipelineContext, start: float) -> StageResult:
            rc = ReconstructionContext(start=start, stage_name=self.name)
            self._prepare_workspace(context, rc)
            phase1_ok = self._dispatch_phase1(context, rc)
            if not phase1_ok:
                return rc.as_failure()
            # ... 18 metot cagri ...
            return self._finalize_result(context, rc)

    **ONEMLI:** Bu dataclass pickle edilemez — ``loop_state`` icindeki
    pre-instantiated engine alanlari serileseemez. Sadece in-process
    kullanim icin.
    """

    # Baslangic zamani ve stage ismi — StageResult insaasi icin.
    start: float = 0.0
    stage_name: str = "reconstruction"

    # StageResult alanlari (Faz 2'de dogrudan bu alanlardan StageResult
    # olusturulacak — mevcut yerel ``artifacts``, ``stats``, ``errors``
    # sozluk/listeleri birebir karsilik).
    artifacts: dict[str, Path] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # Workspace dizinleri — ``_prepare_workspace`` tarafindan doldurulur.
    # Beklenen anahtarlar: "static", "deobfuscated", "reconstructed",
    # "reports", "raw" vb.
    dirs: dict[str, Path] = field(default_factory=dict)

    # Kolayca erisilen alt dizin referanslari (dirs sozlugunun alt kumesi
    # ama sik kullanildigi icin explicit alan).
    workspace_dir: Path | None = None
    binary_path: Path | None = None
    static_dir: Path | None = None
    reconstructed_dir: Path | None = None

    # Phase 1 artifact'lari — step registry yolu ya da eski monolith yolu
    # fark etmeksizin bu dict'e yazilir. Anahtarlar plan §2'de listeli
    # (functions_json, strings_json, call_graph_json, xrefs_json,
    # pcode_json, cfg_json, fid_json, decompiled_json, ...).
    ph1_artifacts: dict[str, Any] = field(default_factory=dict)

    # Feature flag'ler ve early-return durumu.
    used_step_registry: bool = False
    phase1_short_circuit: bool = False
    phase1_early_return: "StageResult | None" = None

    # ---- Analyzer sonuclari (eski monolith Phase 1) ----
    sig_matches: list[Any] = field(default_factory=list)
    byte_pattern_matches: list[Any] = field(default_factory=list)
    # byte_pattern_names: BytePatternMatcher.to_naming_map ciktisi
    # (orig_name -> recovered_name). extracted_names'e merge edilir.
    byte_pattern_names: dict[str, str] = field(default_factory=dict)
    pcode_result: Any = None
    pcode_naming_candidates: list[Any] = field(default_factory=list)
    cfg_result: Any = None
    cfg_naming: Any = None
    algo_result: Any = None
    eng_result: Any = None
    # Confidence calibrated engineering matches (v1.5.1)
    calibrated_matches: Any = None
    extracted_names: dict[str, Any] = field(default_factory=dict)
    capa_capabilities: dict[str, Any] = field(default_factory=dict)
    asm_result: Any = None

    # ---- Decompiled cache (tum asamalarda paylasilir) ----
    decompiled_cache: dict[str, str] = field(default_factory=dict)
    file_cache: dict[str, str] = field(default_factory=dict)

    # ---- Naming ----
    naming_map: dict[str, Any] = field(default_factory=dict)
    symbol_map: dict[str, str] = field(default_factory=dict)

    # ---- Type recovery ----
    types_inferred: dict[str, Any] = field(default_factory=dict)
    structs_recovered: dict[str, Any] = field(default_factory=dict)

    # ---- Feedback loop alt state'i ----
    loop_state: ReconLoopState | None = None

    # ---- Fusion + struct recovery (M4 monolith) ----
    fusion_result: Any = None
    struct_candidates: list[Any] = field(default_factory=list)
    struct_recovery_result: Any = None

    # ---- Iteration ozeti (loop disi kolayca erisim icin) ----
    iteration: int = 0
    max_iterations: int = 5
    converged: bool = False

    def ensure_loop_state(self, max_iterations: int | None = None) -> ReconLoopState:
        """``loop_state`` None ise insa et, degilse mevcut objeyi dondur.

        ``_prepare_feedback_loop`` metoduna (Faz 2) alternatif olarak
        herhangi bir metottan tek satir cagrilabilir.
        """

        if self.loop_state is None:
            self.loop_state = ReconLoopState(
                max_iterations=max_iterations if max_iterations is not None else self.max_iterations
            )
        return self.loop_state


# Geri uyumluluk / takim kolayligi icin takma adlar.
# Plan dokumaninda ``_ReconCtx`` ve ``_ReconLoopState`` private isimler
# kullanilmisti; kamuya acik API icin leading-underscore'suz isimler
# uretiyoruz. Ikisi de ayni objelere isaret eder.
_ReconCtx = ReconstructionContext
_ReconLoopState = ReconLoopState


__all__ = [
    "ReconstructionContext",
    "ReconLoopState",
    "_ReconCtx",
    "_ReconLoopState",
]
