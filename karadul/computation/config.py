"""Hesaplama bazli kurtarma paketinin konfigurasyonu (v1.4.0.alpha).

Bu paket, ``karadul/reconstruction/recovery_layers/`` altindaki eski
``ComputationRecoveryConfig``'ten AYRIDIR. Yeni paket (karadul.computation)
MaxSMT struct layout, CFG isomorphism, signature fusion gibi Blackhat-film
esinli HESAPLAMA BAZLI (LLM'siz) kurtarma bilesenleri icindir.

Tum magic number'lar burada — solver weights, timeouts, thresholds.
Feature flag'ler default kapali; her bilesen bagimsiz acilip kapanir.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ComputationConfig:
    """Hesaplama bazli kurtarma — tum bilesenler icin ortak config.

    Struct Recovery (MaxSMT):
        struct_solver_timeout: Z3 MaxSMT icin saniye cinsinden timeout.
        struct_max_candidates: Synthesizer'in ureteceei maksimum aday sayisi.
        struct_unknown_weight: Objective'de ``unknown_i`` icin cezai agirlik.
        struct_split_weight: Ayni tipi birden fazla class'a bolmenin cezasi.
        struct_union_weight: Ayni offset'te cakisan alanlar (union) cezasi.
        struct_padding_weight: Acik padding (unreferenced alan) cezasi.
        struct_min_confidence: Kabul icin minimum guven [0,1].
        enable_computation_struct_recovery: Feature flag. v1.10.0'da
            **default FALSE** -- Codex teyit raporu (Batch 6C) matematik
            endiselerine dayanarak deneysel komponenti opt-in yapti. Batch
            6A matematik fix'lerinden sonra v1.10.1+'da tekrar True'ya
            cekilebilir. Acmak icin --maxsmt-struct veya YAML
            computation.enable_computation_struct_recovery: true.

    Diger bilesenler (T25 CFG-iso, T26 signature fusion) ileride eklenecek.
    """

    # --- Struct Recovery (MaxSMT) ---
    struct_solver_timeout: float = 60.0
    struct_max_candidates: int = 10
    struct_unknown_weight: float = 1.0
    struct_split_weight: float = 0.5
    struct_union_weight: float = 0.3
    struct_padding_weight: float = 0.1
    struct_min_confidence: float = 0.7
    # v1.10.0 Batch 6C: Codex teyit raporu matematik bug endiselerine dayanarak
    # bu deneysel komponenti opt-in yapti (default KAPALI). Batch 6A matematik
    # fix'lerinden sonra v1.10.1+'da True'ya cekilecek. Acmak icin
    # cli.py --maxsmt-struct veya YAML computation.enable_computation_struct_recovery: true.
    enable_computation_struct_recovery: bool = False

    # v1.10.0 Batch 6D (FIX 5 full): Per-component paralel Z3 solve.
    # max_parallel_workers: None -> CPU_PERF_CORES (auto). Cap 10 (Z3
    # context'leri RAM-heavy, 10+ worker'dan sonra gain diminishing).
    # component_timeout_s: Her tek component icin Z3 optimize timeout'u.
    # enable_parallel_solve: False -> eski sequential solve() fallback.
    # Default True; tek component/kucuk problem otomatik sequential'a duser
    # (spawn overhead amortize olmaz).
    max_parallel_workers: int | None = None
    component_timeout_s: float = 60.0
    enable_parallel_solve: bool = True

    # --- Signature Fusion (v1.10.0 M4 v1.4.0.rc1) ---
    # Log-odds ensemble + Platt calibration. Dempster-Shafer DEGIL
    # (double-counting riski, codex teyit).
    fusion_accept_threshold: float = 0.90
    fusion_reject_threshold: float = 0.30
    fusion_weights_path: str | None = None
    fusion_calibration_enabled: bool = True
    # v1.10.0: Berke karari "ship it" -- default AKTIF. Kapatmak icin
    # cli.py --no-computation-fusion veya YAML computation.enable_computation_fusion: false.
    enable_computation_fusion: bool = True

    # --- CFG Isomorphism feature flag pass-through ---
    # Eski ``ComputationRecoveryConfig.enable_cfg_iso`` Computation (cfg_iso_match
    # step'i ORAdan okur). Buraya ayrica koymuyoruz cunku cfg_iso paketi
    # ComputationRecoveryConfig alanlarini okuyor (matcher._config_from_obj).

    def __post_init__(self) -> None:
        # Hafif sanity — negatif agirlik Z3'de UB.
        if self.struct_solver_timeout <= 0:
            raise ValueError(
                f"struct_solver_timeout > 0 olmali: {self.struct_solver_timeout}",
            )
        if self.struct_max_candidates < 1:
            raise ValueError(
                f"struct_max_candidates >= 1 olmali: {self.struct_max_candidates}",
            )
        for wname in (
            "struct_unknown_weight",
            "struct_split_weight",
            "struct_union_weight",
            "struct_padding_weight",
        ):
            w = getattr(self, wname)
            if w < 0:
                raise ValueError(f"{wname} negatif olamaz: {w}")
        if not (0.0 <= self.struct_min_confidence <= 1.0):
            raise ValueError(
                f"struct_min_confidence [0,1] disinda: {self.struct_min_confidence}",
            )
        if not (0.0 <= self.fusion_reject_threshold <= self.fusion_accept_threshold <= 1.0):
            raise ValueError(
                "fusion thresholds 0 <= reject <= accept <= 1 olmali: "
                f"reject={self.fusion_reject_threshold}, "
                f"accept={self.fusion_accept_threshold}",
            )
        # v1.10.0 Batch 6D: paralel solve parametreleri sanity.
        if self.max_parallel_workers is not None and self.max_parallel_workers < 1:
            raise ValueError(
                f"max_parallel_workers >= 1 olmali: {self.max_parallel_workers}",
            )
        if self.component_timeout_s <= 0:
            raise ValueError(
                f"component_timeout_s > 0 olmali: {self.component_timeout_s}",
            )
