"""Anchor doğrulama -- küçük CFG'lerde false positive önleyici.

Codex kritik uyarısı: CFG-only auto-accept YASAK. 3-4 node'luk basit
CFG'ler (if-then-else, simple loop) sayısız algoritmayla topolojik
izomorfiktir; anchor sinyalleri olmadan "quicksort" demek absürt olur.

Anchor sinyalleri şunlar olabilir:
    - api_calls: Fonksiyon içinden çağrılan API/lib isimleri (örn.
        ``"memcpy"``, ``"malloc"``, ``"AES_encrypt"``).
    - string_refs: Literal string referansları (örn. sorting error
        mesajları, algoritma tag'leri).
    - recursion: CFG içinde self-call var mı (heuristik: api_calls içinde
        fonksiyonun kendi adı).
    - swap_pattern: İki değişkenin eşzamanlı değiş tokuşu (basit blok-içi
        signal; burada template'e ``anchors["swap_pattern"] = True`` ile
        beyan edilir, CFG bazlı tam tespit ayrı bir geliştirme olacak).

``AnchorValidator`` template'in `anchors` dict'ini bakar; küçük CFG'lerde
bu alan boşsa veya query eşleşen sinyalleri taşımıyorsa sonuç
*ambiguous* işaretlenir.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .fingerprint import AttributedCFG
    from .template_db import AlgorithmTemplate


@dataclass
class AnchorOutcome:
    """Anchor doğrulama sonucu.

    Attributes:
        passed: En az bir anchor eşleşmesi bulundu mu.
        ambiguous: Küçük CFG + anchor yok → belirsiz.
        matched_reasons: Insan-okunur eşleşme nedenleri.
        confidence_adjustment: Final confidence'a çarpılacak faktör
            (0.0-1.0). Geçiş yok → `small_cfg_ambiguous_penalty`, tam
            eşleşme → 1.0.
    """
    passed: bool
    ambiguous: bool
    matched_reasons: list[str]
    confidence_adjustment: float


class AnchorValidator:
    """Küçük CFG'lerde false positive'i azaltan doğrulama katmanı.

    Config parametreleri tüm magic number'ları config.py'den alır:
        small_cfg_threshold: Bu node sayısından azı "küçük" sayılır.
        require_anchor_for_small_cfg: True ise küçük CFG + anchor yok →
            ambiguous (validate sonucu `passed=False, ambiguous=True`).
        small_cfg_ambiguous_penalty: Küçük CFG + anchor yok durumunda
            confidence'a uygulanacak çarpan.
    """

    def __init__(
        self,
        small_cfg_threshold: int = 4,
        require_anchor_for_small_cfg: bool = True,
        small_cfg_ambiguous_penalty: float = 0.4,
    ):
        if small_cfg_threshold < 0:
            raise ValueError("small_cfg_threshold negatif olamaz")
        if not 0.0 <= small_cfg_ambiguous_penalty <= 1.0:
            raise ValueError("small_cfg_ambiguous_penalty 0..1 araliginda olmali")
        self.small_cfg_threshold = int(small_cfg_threshold)
        self.require_anchor_for_small_cfg = bool(require_anchor_for_small_cfg)
        self.small_cfg_ambiguous_penalty = float(small_cfg_ambiguous_penalty)

    def validate(
        self,
        template: "AlgorithmTemplate",
        cfg: "AttributedCFG",
    ) -> AnchorOutcome:
        """Anchor uyumunu doğrula.

        Adımlar:
            1. Template anchor bildirimlerini oku.
            2. Query CFG'de karşılık bulunuyor mu kontrol et.
            3. Küçük CFG + anchor yok → ambiguous.

        Returns:
            AnchorOutcome.
        """
        reasons: list[str] = []
        anchors = dict(template.anchors or {})

        # 1. API çağrı anchor'ları
        anchor_apis = self._as_str_set(anchors.get("api_calls"))
        if anchor_apis:
            cfg_apis = {a.lower() for a in cfg.api_calls}
            matched = anchor_apis & cfg_apis
            if matched:
                reasons.append(f"api_match={sorted(matched)[:3]}")

        # 2. String referans anchor'ları
        anchor_strings = self._as_str_set(anchors.get("string_refs"))
        if anchor_strings:
            cfg_strings = {s.lower() for s in cfg.string_refs}
            # "substring" semantiği -- template stringi query'nin içinde geçiyor mu
            matched_str = {
                s for s in anchor_strings
                if any(s in cs for cs in cfg_strings)
            }
            if matched_str:
                reasons.append(f"string_match={sorted(matched_str)[:3]}")

        # 3. Recursion anchor'ı: api_calls içinde template name geçiyor mu
        if bool(anchors.get("recursion", False)):
            name_l = template.name.lower()
            if any(name_l in (a or "").lower() for a in cfg.api_calls):
                reasons.append("recursion_detected")

        # 4. Boolean "flavor" anchor'ları (swap_pattern, divide_and_conquer vb.)
        # CFG'den doğrudan çıkarma bu version'da yapılmıyor -- template
        # tanımında "beyan edilmiş" olması zayıf sinyaldir; küçük CFG'ler
        # için yine de kaydediyoruz (nötr).
        flavor_flags = {
            k for k, v in anchors.items()
            if isinstance(v, bool) and v and k not in {"recursion"}
        }
        if flavor_flags:
            reasons.append(f"flavor_declared={sorted(flavor_flags)[:3]}")

        small = cfg.node_count() < self.small_cfg_threshold
        has_concrete = any(r.startswith(("api_match", "string_match", "recursion_")) for r in reasons)

        if small and self.require_anchor_for_small_cfg and not has_concrete:
            return AnchorOutcome(
                passed=False,
                ambiguous=True,
                matched_reasons=reasons + ["small_cfg_ambiguous"],
                confidence_adjustment=self.small_cfg_ambiguous_penalty,
            )
        return AnchorOutcome(
            passed=True,
            ambiguous=False,
            matched_reasons=reasons,
            confidence_adjustment=1.0,
        )

    @staticmethod
    def _as_str_set(value) -> set[str]:
        if not value:
            return set()
        if isinstance(value, (list, tuple, set, frozenset)):
            return {str(v).lower() for v in value}
        return {str(value).lower()}
