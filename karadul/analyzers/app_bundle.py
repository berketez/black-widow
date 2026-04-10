"""macOS .app bundle analyzer.

Bir .app dizinindeki tum bilesenleri kesfedip
uygun analyzer'larla paralel analiz eder.
"""
from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.analyzers import register_analyzer, get_analyzer
from karadul.config import Config, CPU_PERF_CORES
from karadul.core.target import TargetType, TargetInfo, Language

logger = logging.getLogger(__name__)


@dataclass
class ComponentResult:
    """Tek bir bilesenin analiz sonucu."""
    name: str
    path: str
    component_type: str
    success: bool
    duration: float = 0.0
    functions_found: int = 0
    strings_found: int = 0
    error: str = ""
    artifacts: dict[str, Any] = field(default_factory=dict)


@dataclass
class BundleAnalysisResult:
    """Tum bundle analiz sonucu."""
    bundle_name: str
    bundle_id: str
    bundle_version: str
    total_components: int
    analyzed_components: int
    failed_components: int
    total_functions: int
    total_strings: int
    total_duration: float
    component_results: list[ComponentResult] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.analyzed_components > 0

    def to_dict(self) -> dict:
        return {
            "bundle_name": self.bundle_name,
            "bundle_id": self.bundle_id,
            "bundle_version": self.bundle_version,
            "total_components": self.total_components,
            "analyzed_components": self.analyzed_components,
            "failed_components": self.failed_components,
            "total_functions": self.total_functions,
            "total_strings": self.total_strings,
            "total_duration": round(self.total_duration, 2),
            "component_results": [
                {
                    "name": cr.name,
                    "path": cr.path,
                    "type": cr.component_type,
                    "success": cr.success,
                    "duration": round(cr.duration, 2),
                    "functions": cr.functions_found,
                    "strings": cr.strings_found,
                    "error": cr.error,
                }
                for cr in self.component_results
            ],
        }


# TargetType -> analyzer TargetType mapping
_COMPONENT_TYPE_MAP = {
    "macho_binary": TargetType.MACHO_BINARY,
    "java_jar": TargetType.JAVA_JAR,
    "electron_app": TargetType.ELECTRON_APP,
    "js_bundle": TargetType.JS_BUNDLE,
    "go_binary": TargetType.GO_BINARY,
}


@register_analyzer(TargetType.APP_BUNDLE)
class AppBundleAnalyzer:
    """macOS .app bundle tam analiz.

    Tum bilesenleri (binary, JAR, framework, Electron)
    paralel olarak analiz eder.
    """

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self._max_workers = 1  # Ghidra ayni anda tek instance calisabilir

    def analyze_static(
        self,
        target: TargetInfo,
        workspace: Any,
    ) -> BundleAnalysisResult:
        """Bundle'in tum bilesenlerini analiz et."""
        start = time.monotonic()

        components = target.metadata.get("components", [])
        bundle_name = target.name
        bundle_id = target.metadata.get("bundle_id", "")
        bundle_version = target.metadata.get("bundle_version", "")

        if not components:
            logger.warning("Bundle'da bilesen bulunamadi: %s", bundle_name)
            return BundleAnalysisResult(
                bundle_name=bundle_name,
                bundle_id=bundle_id,
                bundle_version=bundle_version,
                total_components=0,
                analyzed_components=0,
                failed_components=0,
                total_functions=0,
                total_strings=0,
                total_duration=0,
            )

        logger.info(
            "App Bundle analizi: %s (%d bilesen)",
            bundle_name, len(components),
        )

        # Her bilesen icin TargetInfo olustur
        component_targets = []
        for comp in components:
            comp_path = Path(comp["path"])
            comp_type_str = comp["type"]
            target_type = _COMPONENT_TYPE_MAP.get(comp_type_str, TargetType.MACHO_BINARY)

            # Dil tespiti
            lang = Language.UNKNOWN
            if comp_type_str == "java_jar":
                lang = Language.JAVA
            elif comp_type_str == "electron_app":
                lang = Language.JAVASCRIPT

            comp_target = TargetInfo(
                path=comp_path,
                name=comp.get("name", comp_path.name),
                target_type=target_type,
                language=lang,
                file_size=comp.get("size", 0),
                file_hash="",
                metadata={"parent_bundle": bundle_name},
            )
            component_targets.append((comp, comp_target))

        # Paralel analiz
        results: list[ComponentResult] = []
        workers = min(self._max_workers, len(component_targets))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for comp, comp_target in component_targets:
                future = pool.submit(
                    self._analyze_component,
                    comp, comp_target, workspace,
                )
                futures[future] = comp

            for future in as_completed(futures):
                comp = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    results.append(ComponentResult(
                        name=comp.get("name", "unknown"),
                        path=comp.get("path", ""),
                        component_type=comp.get("type", "unknown"),
                        success=False,
                        error=str(exc),
                    ))

        # Sirala: basarili olanlar once, sonra boyuta gore
        results.sort(key=lambda r: (not r.success, -r.functions_found))

        duration = time.monotonic() - start
        analyzed = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success)
        total_funcs = sum(r.functions_found for r in results)
        total_strs = sum(r.strings_found for r in results)

        # Bundle raporu kaydet
        bundle_result = BundleAnalysisResult(
            bundle_name=bundle_name,
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            total_components=len(components),
            analyzed_components=analyzed,
            failed_components=failed,
            total_functions=total_funcs,
            total_strings=total_strs,
            total_duration=duration,
            component_results=results,
        )

        # Workspace'e kaydet
        if workspace:
            try:
                workspace.save_json("static", "bundle_analysis", bundle_result.to_dict())
            except Exception:
                logger.debug("Bundle analysis workspace kaydi basarisiz, atlaniyor", exc_info=True)

        logger.info(
            "Bundle analiz tamamlandi: %d/%d basarili, %d fonksiyon, %.1fs",
            analyzed, len(components), total_funcs, duration,
        )

        return bundle_result

    def _analyze_component(
        self,
        comp: dict,
        comp_target: TargetInfo,
        workspace: Any,
    ) -> ComponentResult:
        """Tek bir bileseni analiz et."""
        start = time.monotonic()
        comp_path = Path(comp["path"])

        if not comp_path.exists():
            return ComponentResult(
                name=comp.get("name", "unknown"),
                path=str(comp_path),
                component_type=comp.get("type", "unknown"),
                success=False,
                error=f"Dosya bulunamadi: {comp_path}",
            )

        try:
            # Uygun analyzer'i bul
            analyzer_cls = get_analyzer(comp_target.target_type)
            analyzer = analyzer_cls(self.config) if self.config else analyzer_cls()

            # Alt-workspace olustur (component bazli)
            comp_workspace = workspace
            if workspace and hasattr(workspace, "create_sub_workspace"):
                comp_workspace = workspace.create_sub_workspace(comp_target.name)

            # Analiz et
            result = analyzer.analyze_static(comp_target, comp_workspace)

            # Sonucu parse et
            functions_found = 0
            strings_found = 0
            if result and hasattr(result, "functions_found"):
                functions_found = result.functions_found
            if result and hasattr(result, "strings_found"):
                strings_found = result.strings_found
            # Fallback: result dict ise
            if isinstance(result, dict):
                functions_found = result.get("functions_found", result.get("function_count", 0))
                strings_found = result.get("strings_found", result.get("string_count", 0))

            duration = time.monotonic() - start
            logger.info(
                "  [OK] %s: %d fonksiyon, %.1fs",
                comp.get("name", comp_path.name), functions_found, duration,
            )

            return ComponentResult(
                name=comp.get("name", comp_path.name),
                path=str(comp_path),
                component_type=comp.get("type", "unknown"),
                success=True,
                duration=duration,
                functions_found=functions_found,
                strings_found=strings_found,
            )

        except Exception as exc:
            duration = time.monotonic() - start
            logger.warning(
                "  [FAIL] %s: %s (%.1fs)",
                comp.get("name", comp_path.name), exc, duration,
            )
            return ComponentResult(
                name=comp.get("name", comp_path.name),
                path=str(comp_path),
                component_type=comp.get("type", "unknown"),
                success=False,
                duration=duration,
                error=str(exc),
            )
