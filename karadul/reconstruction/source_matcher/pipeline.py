"""Source Matching Pipeline -- NpmFingerprinter sonuclarini alip isim recovery yapar.

End-to-end akis:
1. npm_results'tan paket isimlerini al (highlight.js, rxjs, ...)
2. Her paket icin orijinal kaynak kodu cek (SourceResolver)
3. Minified modulu fingerprint'le (ASTFingerprinter)
4. Orijinali fingerprint'le (ASTFingerprinter)
5. Eslesir (StructuralMatcher)
6. Isim mapping olustur (NameMapper)
7. Sonuclari dondur

SourceResolver ve ASTFingerprinter diger developer tarafindan implement edilecek.
Pipeline bu siniflar mevcut degilse graceful degrade eder (uyari verir, bos sonuc dondurur).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .structural_matcher import StructuralMatcher
from .name_mapper import NameMapper

logger = logging.getLogger(__name__)


@dataclass
class SourceMatchResult:
    """Pipeline sonucu."""

    mappings: dict[str, dict[str, str]]  # module_id -> {old_name: new_name}
    stats: dict[str, int] = field(default_factory=lambda: {
        "packages_resolved": 0,
        "modules_processed": 0,
        "functions_matched": 0,
        "names_recovered": 0,
    })

    def __repr__(self) -> str:
        return (
            f"SourceMatchResult("
            f"modules={len(self.mappings)}, "
            f"pkgs={self.stats.get('packages_resolved', 0)}, "
            f"funcs={self.stats.get('functions_matched', 0)}, "
            f"names={self.stats.get('names_recovered', 0)})"
        )

    @property
    def is_empty(self) -> bool:
        return len(self.mappings) == 0


class SourceMatchingPipeline:
    """Tam source matching pipeline.

    NpmFingerprinter eslestirmesinden sonra calisir.
    Her eslesen npm paketi icin:
    1. Orijinal kaynak kodunu bul/indir
    2. Fonksiyon fingerprint'lerini cikar
    3. Minified <-> orijinal fonksiyonlari eslesir
    4. Eslesmelerden isim haritasi olustur

    Config ile kapatilabilir (enabled=False).

    Kullanim:
        pipeline = SourceMatchingPipeline(config)
        result = pipeline.run(modules_dir, npm_results)
        # result.mappings = {"module_42": {"a": "registerLanguage", ...}}
    """

    def __init__(
        self,
        config: Any = None,
        *,
        resolver: Any = None,
        fingerprinter: Any = None,
        min_similarity: float = 0.45,
        max_packages: int = 100,
    ) -> None:
        """
        Args:
            config: Config nesnesi (source_match alani olabilir).
            resolver: SourceResolver instance'i. None ise lazy import dener.
            fingerprinter: ASTFingerprinter instance'i. None ise lazy import dener.
            min_similarity: StructuralMatcher esik degeri.
            max_packages: En fazla kac paket icin kaynak indirilecek.
        """
        self.config = config
        self._resolver = resolver
        self._fingerprinter = fingerprinter
        self.min_similarity = min_similarity
        self.max_packages = max_packages

        # Config'den override
        if config is not None:
            sm_cfg = getattr(config, "source_match", None)
            if sm_cfg is not None:
                self.min_similarity = getattr(sm_cfg, "min_similarity", self.min_similarity)
                self.max_packages = getattr(sm_cfg, "max_packages", self.max_packages)

        self.matcher = StructuralMatcher(min_similarity=self.min_similarity)
        self.name_mapper = NameMapper()

    @property
    def resolver(self) -> Any:
        """Lazy SourceResolver import -- diger developer'in kodu mevcut degilse None."""
        if self._resolver is not None:
            return self._resolver
        try:
            from karadul.reconstruction.source_matcher.source_resolver import SourceResolver
            self._resolver = SourceResolver(self.config)
            return self._resolver
        except ImportError:
            logger.warning(
                "SourceResolver bulunamadi. "
                "karadul.reconstruction.source_matcher.source_resolver modulu henuz yazilmamis olabilir."
            )
            return None

    @property
    def fingerprinter(self) -> Any:
        """Lazy ASTFingerprinter import -- diger developer'in kodu mevcut degilse None."""
        if self._fingerprinter is not None:
            return self._fingerprinter
        try:
            from karadul.reconstruction.source_matcher.ast_fingerprinter import ASTFingerprinter
            self._fingerprinter = ASTFingerprinter()
            return self._fingerprinter
        except ImportError:
            logger.warning(
                "ASTFingerprinter bulunamadi. "
                "karadul.reconstruction.source_matcher.ast_fingerprinter modulu henuz yazilmamis olabilir."
            )
            return None

    def run(
        self,
        modules_dir: Path,
        npm_results: list[Any],
    ) -> SourceMatchResult:
        """Tam pipeline calistir.

        Args:
            modules_dir: Webpack modullerinin bulundugu dizin (*.js dosyalari).
            npm_results: NpmFingerprinter.fingerprint_all() sonucu (NamingResult listesi).

        Returns:
            SourceMatchResult: Isim mapping'leri ve istatistikler.
        """
        result = SourceMatchResult(mappings={})

        # Resolver ve fingerprinter kontrolu
        if self.resolver is None or self.fingerprinter is None:
            logger.warning(
                "SourceMatchingPipeline: SourceResolver veya ASTFingerprinter mevcut degil. "
                "Source matching atlanacak."
            )
            return result

        # npm_results'tan unique paket isimlerini cikar
        packages: set[str] = set()
        module_to_package: dict[str, str] = {}

        for nr in npm_results:
            pkg = getattr(nr, "npm_package", None)
            if pkg:
                packages.add(pkg)
                mid = getattr(nr, "module_id", None)
                if mid:
                    module_to_package[mid] = pkg

        if not packages:
            logger.info("SourceMatchingPipeline: npm eslesmesi yok, source matching atlanacak.")
            return result

        # max_packages siniri
        if len(packages) > self.max_packages:
            logger.warning(
                "SourceMatchingPipeline: %d paket var, max %d ile sinirlandiriliyor.",
                len(packages), self.max_packages,
            )
            packages = set(list(packages)[:self.max_packages])

        logger.info(
            "SourceMatchingPipeline baslatildi: %d paket, %d modul",
            len(packages), len(module_to_package),
        )

        # Her paket icin orijinal kaynak cek ve eslesir
        for pkg_name in sorted(packages):
            try:
                self._process_package(
                    pkg_name, modules_dir, module_to_package, result,
                )
            except Exception as exc:
                logger.warning(
                    "Paket isleme hatasi (%s): %s", pkg_name, exc,
                )

        # Resolver cache temizligi
        if hasattr(self.resolver, "clear_cache"):
            try:
                self.resolver.clear_cache()
            except Exception:
                logger.debug("Target resolve basarisiz, atlaniyor", exc_info=True)

        logger.info(
            "SourceMatchingPipeline tamamlandi: %s", result,
        )

        return result

    def _process_package(
        self,
        pkg_name: str,
        modules_dir: Path,
        module_to_package: dict[str, str],
        result: SourceMatchResult,
    ) -> None:
        """Tek bir npm paketi icin kaynak cek, fingerprint'le, eslesir.

        Args:
            pkg_name: npm paket adi (orn: "highlight.js").
            modules_dir: Modul dizini.
            module_to_package: {module_id: paket_adi} haritasi.
            result: Sonuclarin yazilacagi SourceMatchResult.
        """
        # 1. Orijinal kaynak kodu cek
        source_bundle = self.resolver.resolve(pkg_name)
        if source_bundle is None:
            logger.info(
                "[SOURCE_MATCH] Paket cozumlenemedi (resolver None dondurdu): %s",
                pkg_name,
            )
            return

        result.stats["packages_resolved"] += 1

        # SourceBundle'dan kaynak kodu al
        # SourceResolver'in dondurdugu nesne:
        #   .source_code: str (birlestirilmis kaynak) veya
        #   .files: dict[str, str] (dosya adi -> icerik) olabilir
        original_source = self._get_source_code(source_bundle)
        if not original_source:
            logger.info(
                "[SOURCE_MATCH] Paket kaynak kodu bos: %s", pkg_name,
            )
            return

        logger.info(
            "[SOURCE_MATCH] Paket %s: kaynak kodu cekildi (%d bytes)",
            pkg_name, len(original_source),
        )

        # 2. Bu pakete ait modulleri bul
        pkg_modules = [
            mid for mid, pkg in module_to_package.items()
            if pkg == pkg_name
        ]

        if not pkg_modules:
            logger.info(
                "[SOURCE_MATCH] Paket %s: iliskili modul bulunamadi", pkg_name,
            )
            return

        logger.info(
            "[SOURCE_MATCH] Paket %s: %d modul bulundu: %s",
            pkg_name, len(pkg_modules), pkg_modules[:10],
        )

        # Orijinal kaynak fonksiyonlarini bir kez fingerprint'le (her modul icin tekrar etme)
        try:
            orig_funcs = self.fingerprinter.extract_functions(original_source)
            logger.info(
                "[SOURCE_MATCH] Paket %s: orijinal kaynaktan %d fonksiyon cikarildi",
                pkg_name, len(orig_funcs),
            )
        except Exception as exc:
            logger.warning(
                "[SOURCE_MATCH] Paket %s: orijinal fingerprint hatasi: %s",
                pkg_name, exc,
            )
            orig_funcs = []

        if not orig_funcs:
            logger.info(
                "[SOURCE_MATCH] Paket %s: orijinal kaynakta fonksiyon bulunamadi, atlaniyor",
                pkg_name,
            )
            return

        # 3. Her modul icin eslesir
        for module_id in pkg_modules:
            module_path = modules_dir / f"{module_id}.js"
            if not module_path.exists():
                logger.debug(
                    "[SOURCE_MATCH] Modul dosyasi yok: %s", module_path,
                )
                continue

            try:
                minified_code = module_path.read_text(errors="replace")
            except Exception as exc:
                logger.debug("Modul okunamadi: %s (%s)", module_path, exc)
                continue

            # 4. Fingerprint + match
            try:
                min_funcs = self.fingerprinter.extract_functions(minified_code)
            except Exception as exc:
                logger.warning(
                    "[SOURCE_MATCH] Modul %s: minified fingerprint hatasi: %s",
                    module_id, exc,
                )
                continue

            logger.info(
                "[SOURCE_MATCH] Modul %s: %d minified fonksiyon, %d orijinal fonksiyon",
                module_id, len(min_funcs), len(orig_funcs),
            )

            match_result = self.matcher.match_module(
                minified_code, original_source, self.fingerprinter,
            )

            result.stats["modules_processed"] += 1

            logger.info(
                "[SOURCE_MATCH] Modul %s: %d eslesmis / %d minified (coverage=%.1f%%), "
                "min_similarity=%.2f",
                module_id, match_result.matched, match_result.total_minified,
                match_result.coverage * 100, self.min_similarity,
            )

            if match_result.matched == 0:
                # Log rejected matches for debugging
                if min_funcs and orig_funcs:
                    # Show best potential match that was rejected
                    best_sim = 0.0
                    best_pair = ("?", "?")
                    for mf in min_funcs[:20]:  # limit to avoid O(n^2) explosion
                        for of in orig_funcs[:20]:
                            try:
                                sim = mf.similarity(of)
                                if sim > best_sim:
                                    best_sim = sim
                                    best_pair = (
                                        getattr(mf, "name", "?"),
                                        getattr(of, "name", "?"),
                                    )
                            except Exception:
                                logger.debug("Pipeline adimi basarisiz, atlaniyor", exc_info=True)
                    logger.info(
                        "[SOURCE_MATCH] Modul %s: eslesmesiz -- en iyi potansiyel: "
                        "%s<->%s (sim=%.3f, esik=%.2f)",
                        module_id, best_pair[0], best_pair[1],
                        best_sim, self.min_similarity,
                    )
                continue

            # 5. Isim mapping
            name_map = self.name_mapper.map_names(match_result)
            if name_map:
                result.mappings[module_id] = name_map
                result.stats["functions_matched"] += match_result.matched
                result.stats["names_recovered"] += len(name_map)

                logger.info(
                    "[SOURCE_MATCH] Paket %s, modul %s: %d eslesmis, %d isim recovery",
                    pkg_name, module_id, match_result.matched, len(name_map),
                )
            else:
                logger.info(
                    "[SOURCE_MATCH] Modul %s: %d eslesmis ama isim recovery bos "
                    "(tum isimler 3+ karakter veya skip listesinde olabilir)",
                    module_id, match_result.matched,
                )

    @staticmethod
    def _get_source_code(source_bundle: Any) -> str | None:
        """SourceBundle nesnesinden kaynak kodu cikart.

        SourceResolver farkli formatlarda donebilir:
        - source_code: str -> dogrudan kullan
        - files: dict[str, str] -> tum dosyalari birlestir
        - str -> dogrudan kaynak kodu
        """
        # String ise dogrudan dondur
        if isinstance(source_bundle, str):
            return source_bundle if source_bundle.strip() else None

        # source_code attribute'u
        src = getattr(source_bundle, "source_code", None)
        if src and isinstance(src, str):
            return src

        # files dict'i -- tum dosyalari birlestir
        files = getattr(source_bundle, "files", None)
        if files and isinstance(files, dict):
            combined = "\n".join(files.values())
            return combined if combined.strip() else None

        return None
