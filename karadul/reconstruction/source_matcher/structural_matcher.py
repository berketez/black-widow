"""Yapisal fonksiyon eslestirme -- minified fonksiyonlari orijinal fonksiyonlarla eslestirir.

Greedy eslestirme algoritmasi:
1. Her (minified, orijinal) cifti icin similarity hesapla
2. Similarity'ye gore azalan sirala
3. En yuksek similarity'den basla, cifti esle
4. Eslesen fonksiyonlari listeden cikar
5. min_similarity altindaki eslesmeleri at
6. Toplu tutarlilik kontrolu yap

Diger developer'in ASTFingerprinter ve FunctionFingerprint siniflarini kullanir.
Bu siniflar henuz yazilmamis olabilir -- Protocol ile interface tanimlandi.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable, Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol: Diger developer'in yazacagi FunctionFingerprint icin interface
# ---------------------------------------------------------------------------

@runtime_checkable
class FunctionFingerprintProtocol(Protocol):
    """ASTFingerprinter'in uretecegi fonksiyon parmak izi.

    Diger developer bu protocol'e uygun bir FunctionFingerprint dataclass yazacak.
    Minimum gereksinimler:
    - name: str | None (fonksiyon adi, minified'da tek harf olabilir)
    - param_names: list[str] (parametre isimleri, pozisyonel)
    - similarity(other) -> float metodu (0.0 - 1.0)
    """

    @property
    def name(self) -> str | None: ...

    @property
    def param_names(self) -> list[str]: ...

    def similarity(self, other: Any) -> float: ...


@runtime_checkable
class ASTFingerprintProtocol(Protocol):
    """ASTFingerprinter interface -- diger developer implement edecek.

    extract_functions: JS kaynak kodundan fonksiyon fingerprint'lerini cikarir.
    """

    def extract_functions(self, source_code: str) -> list[FunctionFingerprintProtocol]: ...


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class FunctionMatch:
    """Eslesen bir fonksiyon cifti."""

    minified: Any  # FunctionFingerprint (protocol uyumlu)
    original: Any  # FunctionFingerprint (protocol uyumlu)
    similarity: float

    def __repr__(self) -> str:
        min_name = getattr(self.minified, "name", "?") or "?"
        orig_name = getattr(self.original, "name", "?") or "?"
        return f"FunctionMatch({min_name} -> {orig_name}, sim={self.similarity:.3f})"


@dataclass
class ModuleMatchResult:
    """Tek bir modulun eslestirme sonucu."""

    total_minified: int
    total_original: int
    matched: int
    matches: list[FunctionMatch]
    coverage: float  # matched / total_minified

    def __repr__(self) -> str:
        return (
            f"ModuleMatchResult(minified={self.total_minified}, "
            f"original={self.total_original}, "
            f"matched={self.matched}, "
            f"coverage={self.coverage:.1%})"
        )


# ---------------------------------------------------------------------------
# StructuralMatcher
# ---------------------------------------------------------------------------

class StructuralMatcher:
    """Minified fonksiyonlari orijinal fonksiyonlarla eslestirir.

    Greedy eslestirme algoritmasi kullanir:
    - Tum (minified, orijinal) ciftleri icin similarity skoru hesapla
    - Score'a gore azalan sirala
    - En yuksekten basla, her eslesmede iki fonksiyonu da listeden cikar
    - min_similarity altindaki ciftleri reddet
    - Toplu tutarlilik kontrolu: eslesen oran cok dusukse tum sonuclari reddet

    Neden greedy (Hungarian degil):
    - O(n*m*log(n*m)) vs O(n^3)
    - Pratik sonuclar cok yakin, cunku yuksek similarity'li ciftler genellikle dogru
    - Hungarian implementasyonu daha karmasik, bu asama icin gereksiz
    """

    # Toplu tutarlilik esigi: eslesen fonksiyonlarin orani
    # bu degerin altinda kalirsa tum eslesmeler guvenilmez sayilir
    CONSISTENCY_RATIO = 0.3

    def __init__(self, min_similarity: float = 0.45) -> None:
        """
        Args:
            min_similarity: Minimum benzerlik skoru (0.0-1.0).
                0.45 esbuild bundle'lari icin optimize edilmis esik.
                esbuild minifier isim kisaltma + tree-shaking yapar
                ama string literal'ler ve property access'ler korunur.
                0.65 cok yuksek -> esbuild ciktisinda gercek eslesmeler kacirilir.
                0.35 cok dusuk -> false positive artar.
        """
        if not 0.0 < min_similarity <= 1.0:
            raise ValueError(f"min_similarity 0-1 arasi olmali, verildi: {min_similarity}")
        self.min_similarity = min_similarity

    def match(
        self,
        minified_funcs: list[Any],
        original_funcs: list[Any],
    ) -> list[FunctionMatch]:
        """Minified fonksiyonlari orijinallerle eslestirir.

        Greedy eslestirme:
        1. NxM similarity matrisi hesapla
        2. Duz listeye cevir: [(score, i, j), ...]
        3. Score'a gore azalan sirala
        4. Her (score, i, j) icin:
           - i veya j zaten kullanildiysa: atla
           - score < min_similarity: dur (liste sorted oldugu icin gerisi de dusuk)
           - Eslesme ekle
        5. Toplu tutarlilik kontrolu

        Args:
            minified_funcs: Minified koddaki fonksiyon fingerprint'leri.
            original_funcs: Orijinal koddaki fonksiyon fingerprint'leri.

        Returns:
            Eslesmis fonksiyon ciftleri listesi, similarity'ye gore azalan sirada.
        """
        if not minified_funcs or not original_funcs:
            return []

        n_min = len(minified_funcs)
        n_orig = len(original_funcs)

        # 1. Tum ciftler icin similarity hesapla
        scored_pairs: list[tuple[float, int, int]] = []
        for i, m_func in enumerate(minified_funcs):
            for j, o_func in enumerate(original_funcs):
                try:
                    sim = m_func.similarity(o_func)
                except Exception:
                    logger.debug("Fonksiyon similarity hesaplama basarisiz, atlaniyor", exc_info=True)
                    continue
                if sim >= self.min_similarity:
                    scored_pairs.append((sim, i, j))

        if not scored_pairs:
            return []

        # 2. Score'a gore azalan sirala
        scored_pairs.sort(key=lambda x: x[0], reverse=True)

        # 3. Greedy eslestirme
        used_min: set[int] = set()
        used_orig: set[int] = set()
        matches: list[FunctionMatch] = []

        for score, i, j in scored_pairs:
            if i in used_min or j in used_orig:
                continue
            # Score zaten >= min_similarity (filtrelenmis)
            matches.append(FunctionMatch(
                minified=minified_funcs[i],
                original=original_funcs[j],
                similarity=round(score, 4),
            ))
            used_min.add(i)
            used_orig.add(j)

        # 4. Toplu tutarlilik kontrolu
        # Eslesen oran cok dusukse sonuclari guvenilmez say
        # Kucuk modullerde (<=5 fonksiyon) esigi dusur -- 1 eslesmede bile
        # reddedilmesin
        min_pool = min(n_min, n_orig)
        effective_ratio = self.CONSISTENCY_RATIO
        if min_pool <= 5:
            # Kucuk modullerde 1 eslesmede bile kabul et
            effective_ratio = min(0.15, self.CONSISTENCY_RATIO)
        if min_pool > 0 and len(matches) / min_pool < effective_ratio:
            logger.warning(
                "Toplu tutarlilik kontrolu basarisiz: %d/%d eslesmis (%.1f%% < %.1f%% esik). "
                "Tum eslesmeler reddedildi.",
                len(matches),
                min_pool,
                100 * len(matches) / min_pool,
                100 * effective_ratio,
            )
            return []

        logger.info(
            "StructuralMatcher: %d eslesmis (%d minified, %d orijinal, min_sim=%.2f)",
            len(matches), n_min, n_orig, self.min_similarity,
        )

        return matches

    def match_module(
        self,
        minified_module: str,
        original_source: str,
        fingerprinter: Any,
    ) -> ModuleMatchResult:
        """Tek bir modulun kaynak koduyla eslestir.

        Fingerprinter'dan fonksiyonlari cikarir, sonra match() ile eslestirir.

        Args:
            minified_module: Minified moduldeki JS kaynak kodu.
            original_source: Orijinal JS kaynak kodu.
            fingerprinter: ASTFingerprinter instance'i (extract_functions metodu olmali).

        Returns:
            ModuleMatchResult: Eslestirme istatistikleri ve sonuclar.
        """
        try:
            min_funcs = fingerprinter.extract_functions(minified_module)
        except Exception as exc:
            logger.warning("Minified fonksiyonlar cikarilamadi: %s", exc)
            min_funcs = []

        try:
            orig_funcs = fingerprinter.extract_functions(original_source)
        except Exception as exc:
            logger.warning("Orijinal fonksiyonlar cikarilamadi: %s", exc)
            orig_funcs = []

        matches = self.match(min_funcs, orig_funcs)

        n_min = len(min_funcs)
        coverage = len(matches) / n_min if n_min > 0 else 0.0

        return ModuleMatchResult(
            total_minified=n_min,
            total_original=len(orig_funcs),
            matched=len(matches),
            matches=matches,
            coverage=round(coverage, 4),
        )
