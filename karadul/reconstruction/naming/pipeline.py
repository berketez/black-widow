"""5 Katmanli Hybrid Naming Pipeline.

Katmanlar (sirasıyla):
1.   NpmFingerprinter    -- bilinen npm paketlerini string imzalariyla eslestirir
1.5  SourceMatcher       -- eslesen paketlerin orijinal kaynagindan fonksiyon ismi recovery
2.   StructuralAnalyzer  -- export/class/function isimlerini cikarir, kategori tespit eder
3.   LLMNamer            -- Codex CLI veya heuristic ile kalan modulleri isimlendirir
4.   Conflict Resolution -- ayni dosya adi iki module verilmisse suffix ekler

Her katman oncekinin isimlendiremedigini alir, boylece katmanlar birbirini tamamlar.
Layer 1.5 (source matching) opsiyoneldir -- config.source_match.enabled ile kapatilabilir.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .npm_fingerprinter import NpmFingerprinter
from .structural_analyzer import StructuralAnalyzer
from .llm_namer import LLMNamer
from .result import NamingManifest, NamingResult

if TYPE_CHECKING:
    from karadul.config import Config

logger = logging.getLogger(__name__)


class NamingPipeline:
    """5 katmanli hybrid naming pipeline.

    Kullanim:
        pipeline = NamingPipeline()
        manifest = pipeline.run(modules_dir)
        print(manifest.summary())
        pipeline.apply(modules_dir, output_dir, manifest)

    Source matching opsiyonel:
        pipeline = NamingPipeline(config=config)  # config.source_match.enabled ile kontrol
    """

    def __init__(
        self,
        *,
        config: "Config | None" = None,
        use_codex: bool = True,
        llm_timeout: int = 120,
        skip_llm: bool = False,
    ) -> None:
        """
        Args:
            config: Config nesnesi (source_match ayarlari icin).
            use_codex: Codex CLI kullanilsin mi (kuruluysa).
            llm_timeout: LLM timeout (saniye).
            skip_llm: LLM katmanini tamamen atla (sadece fingerprint + structural).
        """
        self.config = config
        self.fingerprinter = NpmFingerprinter()
        self.structural = StructuralAnalyzer()
        self.llm = LLMNamer(use_codex=use_codex, timeout=llm_timeout)
        self.skip_llm = skip_llm

        # Source matching ayarlari
        self._source_match_enabled = True
        if config is not None:
            sm_cfg = getattr(config, "source_match", None)
            if sm_cfg is not None:
                self._source_match_enabled = getattr(sm_cfg, "enabled", True)

    def run(self, modules_dir: Path) -> NamingManifest:
        """Tum modulleri isimlendir.

        Args:
            modules_dir: Webpack modullerinin bulundugu dizin (*.js dosyalari).

        Returns:
            NamingManifest -- tum sonuclar, istatistikler, conflict resolution yapilmis.
        """
        manifest = NamingManifest()
        all_modules = self._load_module_ids(modules_dir)
        total = len(all_modules)
        t0 = time.monotonic()

        logger.info("NamingPipeline baslatildi: %d modul", total)

        # ---- Layer 1: NPM Fingerprinting ----
        t1 = time.monotonic()
        fp_results = self.fingerprinter.fingerprint_all(modules_dir)
        manifest.add_results(fp_results, "npm_fingerprint")
        named = {r.module_id for r in fp_results}
        logger.info(
            "Layer 1 (npm_fingerprint): %d eslesme (%.1fs)",
            len(fp_results), time.monotonic() - t1,
        )

        # ---- Layer 1.2: DTS Export Naming ----
        # npm fingerprint ile eslesen paketlerin .d.ts dosyalarindan
        # export isimlerini okuyup minified fonksiyonlarla eslestirir.
        # Ilk once lokal arama (node_modules), bulamazsa bilinen paketler
        # icin remote fetch (unpkg.com) yapar.
        if fp_results:
            t12 = time.monotonic()
            try:
                from karadul.reconstruction.dts_namer import DtsNamer
                import re as _re

                # Lokal arama icin network'suz namer
                dts_namer_local = DtsNamer(fetcher=lambda url: None)
                # Remote arama icin network'lu namer (bilinen paketler icin)
                dts_namer_remote = DtsNamer(timeout=8)

                dts_total_matches = 0
                dts_remote_fetched = 0

                # Bilinen Cursor/VS Code bagimliliklari -- remote fetch icin whitelist
                _CURSOR_KNOWN_PACKAGES = {
                    "semver", "chalk", "commander", "yaml", "protobufjs",
                    "node-fetch", "form-data", "graceful-fs", "delayed-stream",
                    "proxy-agent", "highlight.js",
                }

                for fp_result in fp_results:
                    pkg_name = fp_result.npm_package
                    if not pkg_name:
                        continue
                    module_id = fp_result.module_id

                    # Lokal .d.ts arama: workspace'te node_modules varsa
                    dts_found = False
                    dts_exports = []

                    for search_dir in [
                        modules_dir.parent,
                        modules_dir.parent.parent,
                    ]:
                        dts_candidates = [
                            search_dir / "node_modules" / "@types" / pkg_name / "index.d.ts",
                            search_dir / "node_modules" / pkg_name / "index.d.ts",
                            search_dir / "node_modules" / pkg_name / "dist" / "index.d.ts",
                        ]
                        for dts_path in dts_candidates:
                            if dts_path.exists():
                                dts_exports = dts_namer_local.load_dts_from_file(dts_path)
                                if dts_exports:
                                    dts_found = True
                                    break
                        if dts_found:
                            break

                    # Lokal bulunamadiysa ve bilinen paketse remote fetch dene
                    if not dts_exports and pkg_name in _CURSOR_KNOWN_PACKAGES:
                        try:
                            remote_content = dts_namer_remote.fetch_dts_content(pkg_name)
                            if remote_content:
                                dts_exports = dts_namer_remote.parse_dts(remote_content)
                                dts_remote_fetched += 1
                                logger.debug(
                                    "DTS remote fetch basarili: %s (%d export)",
                                    pkg_name, len(dts_exports),
                                )
                        except Exception as exc:
                            logger.debug("DTS remote fetch hatasi (%s): %s", pkg_name, exc)

                    if not dts_exports:
                        continue

                    # Moduldeki export isimlerini cikar
                    js_file = modules_dir / f"{module_id}.js"
                    if not js_file.exists():
                        continue
                    try:
                        js_content = js_file.read_text(errors="replace")
                        export_pattern = _re.compile(
                            r'(?:module\.exports\s*=\s*\{([^}]+)\}|exports\.(\w+)\s*=)'
                        )
                        minified_exports = []
                        for em in export_pattern.finditer(js_content):
                            if em.group(1):
                                for item in em.group(1).split(","):
                                    name = item.strip().split(":")[0].strip()
                                    if name and _re.match(r'^\w+$', name):
                                        minified_exports.append(name)
                            elif em.group(2):
                                minified_exports.append(em.group(2))

                        if minified_exports and dts_exports:
                            match_result = dts_namer_local.match_exports(minified_exports, dts_exports)
                            if match_result.matched:
                                dts_total_matches += len(match_result.matched)
                                manifest.source_match_mappings.setdefault(module_id, {}).update(
                                    match_result.matched
                                )
                    except Exception as exc:
                        logger.debug("DTS export matching hatasi (%s): %s", module_id, exc)

                if dts_total_matches > 0 or dts_remote_fetched > 0:
                    manifest.statistics["dts_naming"] = {
                        "total_exports_matched": dts_total_matches,
                        "remote_fetched": dts_remote_fetched,
                    }
                    logger.info(
                        "Layer 1.2 (dts_naming): %d export eslesti, %d remote fetch (%.1fs)",
                        dts_total_matches, dts_remote_fetched, time.monotonic() - t12,
                    )
            except ImportError:
                logger.debug("Layer 1.2 (dts_naming): DtsNamer modulu bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Layer 1.2 (dts_naming): hata, atlaniyor: %s", exc)

        # ---- Layer 1.5: Source Matching (opsiyonel) ----
        # npm fingerprint sonuclarindan eslesen paketlerin orijinal kaynagini
        # cekip fonksiyon bazli eslestirme yapar ve degisken isimlerini recovery eder.
        source_match_result = None
        if fp_results and self._source_match_enabled:
            t15 = time.monotonic()
            try:
                from karadul.reconstruction.source_matcher.pipeline import (
                    SourceMatchingPipeline,
                )
                source_pipeline = SourceMatchingPipeline(
                    config=self.config,
                )
                source_match_result = source_pipeline.run(modules_dir, fp_results)
                if source_match_result and not source_match_result.is_empty:
                    manifest.statistics["source_match"] = source_match_result.stats
                    logger.info(
                        "Layer 1.5 (source_match): %d modul, %d fonksiyon, %d isim (%.1fs)",
                        len(source_match_result.mappings),
                        source_match_result.stats.get("functions_matched", 0),
                        source_match_result.stats.get("names_recovered", 0),
                        time.monotonic() - t15,
                    )
                else:
                    logger.info(
                        "Layer 1.5 (source_match): eslesmis isim yok (%.1fs)",
                        time.monotonic() - t15,
                    )
            except ImportError:
                logger.debug(
                    "Layer 1.5 (source_match): source_matcher modulu mevcut degil, atlaniyor."
                )
            except Exception as exc:
                logger.warning(
                    "Layer 1.5 (source_match): hata, atlaniyor: %s", exc,
                )

        # ---- Layer 2: Structural Analysis ----
        t2 = time.monotonic()
        st_results = self.structural.analyze_all(modules_dir, named)
        manifest.add_results(st_results, "structural")
        named.update(r.module_id for r in st_results)
        logger.info(
            "Layer 2 (structural): %d isimlendirildi (%.1fs)",
            len(st_results), time.monotonic() - t2,
        )

        # ---- Layer 3: LLM / Heuristic (kalan moduller) ----
        remaining_ids = all_modules - named
        if remaining_ids and not self.skip_llm:
            t3 = time.monotonic()
            remaining = []
            for mid in sorted(remaining_ids):
                js_file = modules_dir / f"{mid}.js"
                if js_file.exists():
                    try:
                        content = js_file.read_text(errors="replace")
                        remaining.append((mid, content))
                    except Exception:
                        logger.debug("Dosya okuma basarisiz, atlaniyor", exc_info=True)

            if remaining:
                llm_results = self.llm.name_modules(remaining)
                manifest.add_results(llm_results, "llm_assisted")
                named.update(r.module_id for r in llm_results)
                logger.info(
                    "Layer 3 (llm/heuristic): %d isimlendirildi (%.1fs)",
                    len(llm_results), time.monotonic() - t3,
                )

        # ---- Layer 4: Conflict Resolution ----
        conflicts = manifest.resolve_conflicts()
        if conflicts > 0:
            logger.info("Layer 4: %d conflict cozuldu", conflicts)

        elapsed = time.monotonic() - t0
        logger.info(
            "NamingPipeline tamamlandi: %d/%d modul isimlendirildi (%.1fs)",
            len(manifest.results), total, elapsed,
        )

        # Source match sonuclarini manifest'e ekle (downstream kullanim icin)
        # manifest.source_match_mappings: {module_id: {old_name: new_name}}
        # Layer 1.2 (DTS naming) zaten source_match_mappings'e yazmis olabilir,
        # bu yuzden mevcut degerleri koruyoruz ve source_match sonuclarini
        # merge ediyoruz.
        if source_match_result and not source_match_result.is_empty:
            # Source match sonuclarini mevcut DTS mappings'in uzerine merge et
            for mod_id, mappings in source_match_result.mappings.items():
                manifest.source_match_mappings.setdefault(mod_id, {}).update(mappings)
        # Eger source_match_result yoksa, Layer 1.2 DTS mappings'lerini koru
        # (manifest.source_match_mappings zaten dolu olabilir)

        return manifest

    def apply(
        self,
        modules_dir: Path,
        output_dir: Path,
        manifest: NamingManifest,
    ) -> Path:
        """Manifest'e gore dosyalari yeniden adlandir ve klasorlere tasi.

        Eger source_match_mappings varsa, kopyalama sirasinda minified
        degisken isimlerini orijinale cevirerek yazar.

        Args:
            modules_dir: Kaynak modul dizini.
            output_dir: Hedef cikti dizini.
            manifest: NamingManifest sonuclari.

        Returns:
            output_dir yolu.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        copied = 0
        skipped = 0
        source_match_applied = 0

        # Source match applier (lazy -- sadece mapping varsa import et)
        applier = None
        sm_mappings = getattr(manifest, "source_match_mappings", {}) or {}
        if sm_mappings:
            try:
                from karadul.reconstruction.source_matcher.applier import SourceMatchApplier
                applier = SourceMatchApplier()
            except ImportError:
                logger.debug("SourceMatchApplier bulunamadi, source rename atlaniyor")

        for module_id, result in manifest.results.items():
            src = modules_dir / f"{module_id}.js"
            if not src.exists():
                skipped += 1
                continue

            # Hedef yol: output_dir / category / new_filename
            dest_dir = output_dir / result.category
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / result.new_filename

            # Source match mapping varsa uygula, yoksa sadece kopyala
            module_mapping = sm_mappings.get(module_id)
            if applier is not None and module_mapping:
                count = applier.apply_to_file(src, module_mapping, dest)
                if count > 0:
                    source_match_applied += count
                else:
                    # Mapping vardi ama replacement olmadi -- sadece kopyala
                    shutil.copy2(src, dest)
            else:
                shutil.copy2(src, dest)
            copied += 1

        # Isimlendirilmemis modulleri "unnamed/" altina kopyala
        all_ids = self._load_module_ids(modules_dir)
        unnamed_ids = all_ids - set(manifest.results.keys())
        if unnamed_ids:
            unnamed_dir = output_dir / "unnamed"
            unnamed_dir.mkdir(parents=True, exist_ok=True)
            for mid in sorted(unnamed_ids):
                src = modules_dir / f"{mid}.js"
                if src.exists():
                    # Unnamed modullere de source match uygula (varsa)
                    mid_mapping = sm_mappings.get(mid)
                    if applier is not None and mid_mapping:
                        count = applier.apply_to_file(
                            src, mid_mapping, unnamed_dir / f"{mid}.js",
                        )
                        if count > 0:
                            source_match_applied += count
                        else:
                            shutil.copy2(src, unnamed_dir / f"{mid}.js")
                    else:
                        shutil.copy2(src, unnamed_dir / f"{mid}.js")

        # Manifest'i kaydet
        manifest.save(output_dir / "naming-manifest.json")

        # Index dosyasi yaz
        self._write_index(output_dir, manifest)

        logger.info(
            "Apply tamamlandi: %d kopyalandi, %d atlanildi, %d unnamed, "
            "%d source_match replacement",
            copied, skipped, len(unnamed_ids), source_match_applied,
        )

        return output_dir

    def _load_module_ids(self, modules_dir: Path) -> set[str]:
        """Dizindeki tum modul ID'lerini dondur (uzantisiz dosya isimleri)."""
        return {f.stem for f in modules_dir.glob("*.js")}

    def _write_index(self, output_dir: Path, manifest: NamingManifest) -> None:
        """Cikti dizinine index.json yaz -- kategori bazli agac yapisi."""
        from collections import defaultdict

        tree: dict[str, list[dict]] = defaultdict(list)
        for mid, result in manifest.results.items():
            tree[result.category].append({
                "original": result.original_file,
                "renamed": result.new_filename,
                "description": result.description,
                "confidence": result.confidence,
                "source": result.source,
            })

        # Kategori bazli sirala
        sorted_tree = {}
        for cat in sorted(tree.keys()):
            sorted_tree[cat] = sorted(tree[cat], key=lambda x: x["renamed"])

        index = {
            "summary": manifest.summary(),
            "tree": sorted_tree,
        }

        with open(output_dir / "index.json", "w") as f:
            json.dump(index, f, indent=2, ensure_ascii=False)
