"""Hibrit CFG eşleştirme orkestratörü.

Pipeline (Codex tarafından onaylı):
    1. WL fingerprint + LSH → O(n·k) aday üretimi (top-K template).
    2. VF2 exact subgraph isomorphism rerank (küçük K'da hızlı).
    3. AnchorValidator → küçük CFG false positive koruması.
    4. Confidence skorla, descending sırala, `min_confidence` üstünde kalanları döner.

Tek adımlı (LSH-only veya VF2-only) kullanım **yasak** -- Codex uyarısı
birebir. Ama caller isterse feature flag ile belli aşamayı bypass
edebilir; bu sürümde flag yok, pipeline sabit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .anchor_check import AnchorValidator, AnchorOutcome
from .fingerprint import AttributedCFG, weisfeiler_lehman_hash
from .lsh_index import LSHIndex
from .vf2_matcher import is_networkx_available, vf2_match, vf2_match_with_timeout

if TYPE_CHECKING:  # pragma: no cover
    from .template_db import AlgorithmTemplate


@dataclass
class CFGMatch:
    """Tek template için eşleşme çıktısı.

    match_type:
        - "exact": VF2 izomorfik + anchor tamam.
        - "approximate": LSH similarity yüksek ama VF2 başarısız ve küçük
            CFG değil (topolojik yakın, yapısal varyasyon).
        - "ambiguous": Küçük CFG + anchor yok -> belirsiz.
    """
    template_name: str
    confidence: float
    match_type: str
    reasons: list[str] = field(default_factory=list)
    family: str = "generic"


@dataclass
class _MatcherConfig:
    """İç config proxy -- caller Config veya kwargs geçirir."""
    wl_iterations: int = 3
    lsh_num_hashes: int = 128
    # v1.10.0 Batch 6A: band_size 4 -> 8 (Codex audit, false-positive dusurur).
    lsh_band_size: int = 8
    top_k_candidates: int = 10
    min_confidence: float = 0.7
    anchor_required_for_small_cfg: bool = True
    small_cfg_threshold: int = 4
    small_cfg_penalty: float = 0.4
    # v1.10.0 Batch 6A: 5s -> 30s, hard-stop ile korumali.
    vf2_timeout_s: float = 30.0


def _config_from_obj(cfg_obj) -> _MatcherConfig:
    """Karadul Config / ComputationRecoveryConfig / dict'ten parametre çıkar.

    Yalnızca ilgilendiğimiz alanları aynı isimle aradığımızdan, farklı
    config tipleriyle (dict, dataclass) uyum sağlar.
    """
    mc = _MatcherConfig()
    if cfg_obj is None:
        return mc
    # ComputationRecoveryConfig içinde bu alanlar var (config.py'de ekledik).
    def _get(name: str, default):
        if isinstance(cfg_obj, dict):
            return cfg_obj.get(name, default)
        return getattr(cfg_obj, name, default)

    mc.wl_iterations = int(_get("cfg_iso_num_wl_iterations", mc.wl_iterations))
    mc.lsh_num_hashes = int(_get("cfg_iso_lsh_num_hashes", mc.lsh_num_hashes))
    mc.lsh_band_size = int(_get("cfg_iso_lsh_band_size", mc.lsh_band_size))
    mc.top_k_candidates = int(_get("cfg_iso_top_k_candidates", mc.top_k_candidates))
    mc.min_confidence = float(_get("cfg_iso_min_confidence", mc.min_confidence))
    mc.anchor_required_for_small_cfg = bool(
        _get("cfg_iso_anchor_required_for_small_cfg", mc.anchor_required_for_small_cfg)
    )
    mc.small_cfg_threshold = int(_get("cfg_iso_small_cfg_threshold", mc.small_cfg_threshold))
    mc.small_cfg_penalty = float(_get("cfg_iso_small_cfg_penalty", mc.small_cfg_penalty))
    mc.vf2_timeout_s = float(_get("cfg_iso_vf2_timeout_s", mc.vf2_timeout_s))
    return mc


class HybridCFGMatcher:
    """Hibrit matcher: LSH funnel + VF2 rerank + anchor doğrulama.

    Feature flag:
        Bu sınıfın yapıcısı ``enable_cfg_iso`` flag'ini kontrol ETMEZ --
        kontrol caller sorumluluğunda. ``ComputationRecoveryConfig.enable_cfg_iso``
        False ise bu pipeline çağırılmamalı.
    """

    def __init__(
        self,
        config,
        templates: list["AlgorithmTemplate"],
    ):
        self.config = config
        self.templates = list(templates)
        self._mc = _config_from_obj(config)
        self.lsh_index = LSHIndex(
            self.templates,
            num_hashes=self._mc.lsh_num_hashes,
            band_size=self._mc.lsh_band_size,
            wl_iterations=self._mc.wl_iterations,
        )
        self.anchor_validator = AnchorValidator(
            small_cfg_threshold=self._mc.small_cfg_threshold,
            require_anchor_for_small_cfg=self._mc.anchor_required_for_small_cfg,
            small_cfg_ambiguous_penalty=self._mc.small_cfg_penalty,
        )
        # H1: template WL hash cache — build'de hesapla, query'de yeniden
        # hesaplama. Template'ler immutable, WL hash tamamen deterministik.
        # Tipik bank 10-20 template, her biri ~5-50 ms hash -> 200+ ms
        # kazanc/query.
        self._template_hash_cache: dict[str, str] = {}
        for tmpl in self.templates:
            self._template_hash_cache[tmpl.name] = weisfeiler_lehman_hash(
                tmpl.cfg,
                num_iterations=self._mc.wl_iterations,
            )

    def match(
        self,
        cfg: AttributedCFG,
        top_k: int | None = None,
    ) -> list[CFGMatch]:
        """Hibrit pipeline ile eşleştir.

        Returns:
            `CFGMatch` listesi, confidence descending sırada.  `min_confidence`
            altında kalanlar filtrelenir.
        """
        if not self.templates or cfg.node_count() == 0:
            return []

        k = int(top_k) if top_k is not None else self._mc.top_k_candidates
        query_hash = weisfeiler_lehman_hash(cfg, num_iterations=self._mc.wl_iterations)

        # 1. LSH aday üretimi
        candidates = self.lsh_index.query(cfg, top_k=k)
        # Hiç aday çıkmadıysa yine de en küçük aday seti için tüm template'leri
        # rerank edebilirdik -- ama Codex "tek algoritma yetmez" uyarısını
        # dinleyerek hiç band match yoksa boş dönüyoruz (gereksiz false
        # positive'e izin verme).
        if not candidates:
            return []

        results: list[CFGMatch] = []
        for template in candidates:
            result = self._rerank_candidate(template, cfg, query_hash)
            if result is not None:
                results.append(result)

        # Confidence descending, tie-break name
        results.sort(key=lambda m: (-m.confidence, m.template_name))
        # min_confidence filtre
        results = [r for r in results if r.confidence >= self._mc.min_confidence]
        return results

    def _rerank_candidate(
        self,
        template: "AlgorithmTemplate",
        cfg: AttributedCFG,
        query_hash: str,
    ) -> CFGMatch | None:
        """Tek aday için VF2 + anchor değerlendirmesi."""
        reasons: list[str] = []
        base_confidence = self.lsh_index.similarity(cfg, template.cfg)
        reasons.append(f"lsh_similarity={base_confidence:.3f}")

        # WL exact hash eşleşmesi -- baseline artırıcı.
        # H1: cache'den oku; isim bulunmazsa fallback olarak hesapla
        # (savunmaci — dinamik template eklenmesi halinde).
        template_hash = self._template_hash_cache.get(template.name)
        if template_hash is None:
            template_hash = weisfeiler_lehman_hash(
                template.cfg,
                num_iterations=self._mc.wl_iterations,
            )
            self._template_hash_cache[template.name] = template_hash
        wl_exact = (query_hash == template_hash)
        if wl_exact:
            reasons.append("wl_hash_exact")
            base_confidence = max(base_confidence, 0.90)

        # VF2 exact (v1.10.0 C1: timeout korumalı)
        vf2_exact = False
        if is_networkx_available():
            try:
                if self._mc.vf2_timeout_s > 0:
                    vf2_exact, vf2_timed_out = vf2_match_with_timeout(
                        cfg, template.cfg,
                        timeout_s=self._mc.vf2_timeout_s,
                    )
                    if vf2_timed_out:
                        reasons.append(
                            f"vf2_timeout={self._mc.vf2_timeout_s}s"
                        )
                else:
                    vf2_exact = vf2_match(cfg, template.cfg)
            except Exception as exc:  # pragma: no cover - defensive
                reasons.append(f"vf2_error={type(exc).__name__}")
                vf2_exact = False
            if vf2_exact:
                reasons.append("vf2_exact_match")
                base_confidence = max(base_confidence, 0.95)
        else:
            reasons.append("vf2_skipped_no_networkx")

        # Anchor doğrulama
        anchor_out: AnchorOutcome = self.anchor_validator.validate(template, cfg)
        reasons.extend(anchor_out.matched_reasons)
        adjusted = base_confidence * anchor_out.confidence_adjustment

        # Match tipini belirle
        if anchor_out.ambiguous:
            match_type = "ambiguous"
        elif vf2_exact:
            match_type = "exact"
        else:
            match_type = "approximate"

        return CFGMatch(
            template_name=template.name,
            confidence=round(adjusted, 4),
            match_type=match_type,
            reasons=reasons,
            family=template.family,
        )
