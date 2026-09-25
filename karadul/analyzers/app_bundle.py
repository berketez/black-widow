"""macOS .app bundle analyzer.

Bir .app dizinindeki tüm bileşenleri keşfedip uygun analyzer'larla SIRAYLA
analiz eder. Her bileşen kendi alt-workspace'ine yazar
(``<workspace>/components/<bileşen>/``); en çok fonksiyonu olan başarılı
bileşen "ana bileşen" olur ve çıktıları üst workspace'e taşınır (downstream
stage'ler, raporlar ve arayüz üst workspace'i okur).
"""
from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.analyzers import register_analyzer, get_analyzer
from karadul.config import Config
from karadul.core.target import (
    _UNIVERSAL_MAGIC,
    Language,
    TargetDetector,
    TargetInfo,
    TargetType,
)

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
    # Bileşenin alt-workspace'i, üst workspace'e GÖRELİ yol
    # (ör. "components/Tiny"). Workspace yoksa boş.
    workspace: str = ""


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

    @property
    def main_component(self) -> ComponentResult | None:
        """En çok fonksiyonu olan başarılı bileşen (eşitlikte listede ilk olan)."""
        successful = [r for r in self.component_results if r.success]
        if not successful:
            return None
        return max(successful, key=lambda r: r.functions_found)

    def to_dict(self) -> dict:
        main = self.main_component
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
            "main_component": main.name if main else "",
            "main_component_path": main.path if main else "",
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
                    "workspace": cr.workspace,
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

# Bileşen analyzer'ının StageResult.stats'ındaki sayaç anahtarları. Öncelik
# sırası CLI sonuç tablosu / JSON rapor ile aynı (functions_found ->
# ghidra_function_count -> functions): paket bileşeni, aynı binary tek başına
# analiz edildiğinde görülen sayıyı raporlar. MachOAnalyzer yalnız
# ghidra_function_count / ghidra_string_count / string_count yazıyor.
_FUNCTION_COUNT_KEYS = (
    "functions_found", "ghidra_function_count", "functions", "function_count",
)
_STRING_COUNT_KEYS = (
    "strings_found", "ghidra_string_count", "string_count", "strings",
)

# Ana bileşenden üst workspace'e taşınan stage dizinleri. ghidra_project
# Ghidra'nın geçici proje dizini (analiz sonunda silinir), taşınmaz.
_PROMOTED_STAGES = ("raw", "static", "deobfuscated")
_NOT_PROMOTED = frozenset({"ghidra_project"})

_HASH_CHUNK = 1024 * 1024


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(_HASH_CHUNK), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _is_universal_macho(path: Path) -> bool:
    """Fat (universal) Mach-O mu? Karar TargetDetector'ınkiyle aynı (tek kaynak)."""
    return (
        TargetDetector._read_magic(path) == _UNIVERSAL_MAGIC
        and not TargetDetector._is_java_class(path)
    )


def build_component_target(comp: dict[str, Any], bundle_name: str) -> TargetInfo:
    """Paket bileşeni için TargetInfo.

    Statik analiz ve reconstruction AYNI tanımı kullanır: hedef yolu .app
    dizini DEĞİL bileşenin gerçek dosyasıdır. Bundle context'iyle çalışan
    adımlar (binary_prep -> byte_pattern / anti_debug / packer_fingerprint)
    eskiden .app dizinini dosya sanıp "Hedef dosya bulunamadi" / "Is a
    directory" veriyordu.

    Fat (universal) Mach-O bileşen UNIVERSAL_BINARY olur -- aynı dosya tek
    başına analiz edildiğinde olduğu gibi: MachOAnalyzer ince dilimi
    (raw/<ad>_arm64) çıkarıp Ghidra'ya onu verir, binary_prep de bayt
    eşleştirmeyi o dilimde yapar. TargetDetector paket bileşenlerini hep
    "macho_binary" diye listeler; MACHO_BINARY kalsaydı Ghidra fat dosyanın
    İLK dilimini (SafariForWebKitDevelopment'ta arm64 yerine x86_64)
    yüklüyor, bayt tarayıcıları ise fat dosyayı okuyordu (ofsetler tutmaz).

    file_hash bileşenin kendi SHA-256'sıdır (manuel isim override deposu ve
    computation önbelleği binary hash'iyle anahtarlanır; bundle'ın hash'i en
    büyük Mach-O'nunkidir, ana bileşenle aynı olmayabilir).
    """
    comp_path = Path(comp["path"])
    comp_type_str = comp.get("type", "macho_binary")
    target_type = _COMPONENT_TYPE_MAP.get(comp_type_str, TargetType.MACHO_BINARY)
    if target_type == TargetType.MACHO_BINARY and _is_universal_macho(comp_path):
        target_type = TargetType.UNIVERSAL_BINARY

    lang = Language.UNKNOWN
    if comp_type_str == "java_jar":
        lang = Language.JAVA
    elif comp_type_str == "electron_app":
        lang = Language.JAVASCRIPT

    size = comp.get("size")
    if not isinstance(size, int):
        try:
            size = comp_path.stat().st_size if comp_path.is_file() else 0
        except OSError:
            size = 0

    return TargetInfo(
        path=comp_path,
        name=comp.get("name", comp_path.name),
        target_type=target_type,
        language=lang,
        file_size=size,
        file_hash=_sha256(comp_path) if comp_path.is_file() else "",
        metadata={"parent_bundle": bundle_name, "bundle_component": True},
    )


def component_context(context: Any, component_target: TargetInfo) -> Any:
    """Bundle PipelineContext'inin hedefi ana bileşene çevrilmiş kopyası.

    workspace / config / results / metadata / progress callback AYNI nesneler
    (dataclasses.replace yüzeysel kopya); yalnız ``target`` değişir. Böylece
    reconstruction adımları (pc.target.path, target_type, file_hash) paketin
    .app dizinini değil ana bileşenin binary'sini görür.
    """
    return dataclasses.replace(context, target=component_target)


def _link_or_copy(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
    """Hardlink (aynı disk, yer kaplamaz); olmazsa kopya."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def promote_component_outputs(workspace: Any, component_workspace: str) -> list[str]:
    """Ana bileşenin raw/static/deobfuscated çıktılarını üst workspace'e taşı.

    Reconstruction, raporlar, OutputFormatter ve arayüz üst workspace'in
    ``static/`` ve ``reconstructed/`` dizinlerini okur. Bileşenler kendi
    alt-workspace'lerine yazdığı için ana bileşenin çıktıları buraya
    hardlink'lenir (hardlink yoksa kopyalanır). Üst düzeyde zaten olan
    dosyalar (bundle_analysis.json, target_info.json) EZİLMEZ.

    Returns:
        Taşınan girdiler ("static/ghidra_functions.json" gibi).
    """
    root = Path(workspace.path).resolve()
    src_root = (root / component_workspace).resolve()
    # Göreli yol üst workspace dışına çıkmasın (ValueError).
    src_root.relative_to(root)
    if src_root == root:
        raise ValueError(f"Bileşen workspace'i üst workspace olamaz: {component_workspace}")

    promoted: list[str] = []
    for stage in _PROMOTED_STAGES:
        src_stage = src_root / stage
        if not src_stage.is_dir():
            continue
        dst_stage = Path(workspace.get_stage_dir(stage))
        for entry in sorted(src_stage.iterdir()):
            if entry.name in _NOT_PROMOTED:
                continue
            dst = dst_stage / entry.name
            if dst.exists() or dst.is_symlink():
                logger.debug("Üst workspace'te zaten var, taşınmadı: %s", dst)
                continue
            if entry.is_dir():
                shutil.copytree(entry, dst, copy_function=_link_or_copy)
            else:
                _link_or_copy(entry, dst)
            promoted.append(f"{stage}/{entry.name}")
    return promoted


def _first_count(sources: list[Any], keys: tuple[str, ...]) -> int:
    """Kaynaklarda (dict ya da nitelik) ilk tamsayı sayacı döndür."""
    for src in sources:
        for key in keys:
            if isinstance(src, dict):
                val = src.get(key)
            else:
                val = getattr(src, key, None)
            if isinstance(val, int) and not isinstance(val, bool):
                return val
    return 0


def _component_outcome(result: Any) -> tuple[bool, int, int, str]:
    """Bileşen analyzer sonucundan (başarı, fonksiyon, string, hata) çıkar.

    Analyzer'lar StageResult döndürür; sayaçlar ``result.stats`` içindedir.
    Eski kod ``result.functions_found`` niteliğine bakıyordu -- StageResult'ta
    böyle bir nitelik yok, bu yüzden her bileşen 0 fonksiyon raporluyordu.
    """
    if result is None:
        return False, 0, 0, "analyzer sonuç döndürmedi"

    sources: list[Any] = []
    stats = getattr(result, "stats", None)
    if isinstance(stats, dict):
        sources.append(stats)
    if isinstance(result, dict):
        sources.append(result)
    sources.append(result)

    functions = _first_count(sources, _FUNCTION_COUNT_KEYS)
    strings = _first_count(sources, _STRING_COUNT_KEYS)

    if isinstance(result, dict):
        success = bool(result.get("success", True))
        errors = result.get("errors") or []
    else:
        success_attr = getattr(result, "success", True)
        success = success_attr if isinstance(success_attr, bool) else True
        errors = getattr(result, "errors", None) or []
    error = ""
    if not success:
        error = "; ".join(str(e) for e in errors) if isinstance(errors, list) else str(errors)
        error = error or "bileşen analizi başarısız"
    return success, functions, strings, error


@register_analyzer(TargetType.APP_BUNDLE)
class AppBundleAnalyzer:
    """macOS .app bundle tam analiz.

    Tüm bileşenleri (binary, JAR, framework, Electron) SIRAYLA ve çağıran
    thread'de analiz eder. Eskiden tek işçili (max_workers=1) bir
    ThreadPoolExecutor kullanılıyordu: paralellik yoktu, ama Ghidra JVM'i işçi
    thread'inde doğuyordu. JNI_CreateJavaVM'i çağıran thread JVM'de daemon
    olmayan "main" thread'i olarak kalır; işçi bitince JVM'den ayrılmadığı için
    çıkışta DestroyJavaVM sonsuza kadar bekliyordu (2026-09-25, jstack ile
    ölçüldü). Ghidra zaten aynı anda tek analiz çalıştırır; sırayla çalışmak
    bir şey kaybettirmez.
    """

    def __init__(self, config: Config | None = None):
        self.config = config or Config()

    def analyze_static(
        self,
        target: TargetInfo,
        workspace: Any,
    ) -> BundleAnalysisResult:
        """Bundle'ın tüm bileşenlerini analiz et."""
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

        # Sıralı analiz (çağıran thread'de) -- bkz. sınıf docstring'i.
        results: list[ComponentResult] = []
        for comp in components:
            try:
                comp_target = build_component_target(comp, bundle_name)
                results.append(
                    self._analyze_component(comp, comp_target, workspace),
                )
            except Exception as exc:
                logger.warning(
                    "  [FAIL] %s: %s", comp.get("name", "unknown"), exc,
                )
                results.append(ComponentResult(
                    name=comp.get("name", "unknown"),
                    path=comp.get("path", ""),
                    component_type=comp.get("type", "unknown"),
                    success=False,
                    error=str(exc),
                ))

        # Sırala: başarılı olanlar önce, sonra fonksiyon sayısına göre
        # (sort kararlı: eşitlikte keşif sırası korunur).
        results.sort(key=lambda r: (not r.success, -r.functions_found))

        duration = time.monotonic() - start
        analyzed = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success)
        total_funcs = sum(r.functions_found for r in results if r.success)
        total_strs = sum(r.strings_found for r in results if r.success)

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
        """Tek bir bileşeni kendi alt-workspace'inde analiz et."""
        start = time.monotonic()
        comp_path = Path(comp["path"])
        name = comp.get("name", comp_path.name)
        comp_type = comp.get("type", "unknown")

        if not comp_path.exists():
            return ComponentResult(
                name=name,
                path=str(comp_path),
                component_type=comp_type,
                success=False,
                error=f"Dosya bulunamadi: {comp_path}",
            )

        comp_ws_rel = ""
        try:
            # Uygun analyzer'i bul
            analyzer_cls = get_analyzer(comp_target.target_type)
            analyzer = analyzer_cls(self.config) if self.config else analyzer_cls()

            # Bileşen başına izole alt-workspace. Eskiden hasattr() koruması
            # Workspace'te olmayan bir metodu arıyordu -> sessizce paylaşılan
            # workspace'e düşüp bileşenler birbirinin static/ çıktısını eziyordu.
            comp_workspace = None
            if workspace is not None:
                comp_workspace = workspace.create_sub_workspace(comp_target.name)
                try:
                    comp_ws_rel = str(
                        Path(comp_workspace.path).resolve().relative_to(
                            Path(workspace.path).resolve(),
                        ),
                    )
                except (TypeError, ValueError):
                    comp_ws_rel = str(comp_workspace.path)

            result = analyzer.analyze_static(comp_target, comp_workspace)
            success, functions_found, strings_found, error = _component_outcome(result)

            duration = time.monotonic() - start
            logger.info(
                "  [%s] %s: %d fonksiyon, %.1fs",
                "OK" if success else "FAIL", name, functions_found, duration,
            )

            return ComponentResult(
                name=name,
                path=str(comp_path),
                component_type=comp_type,
                success=success,
                duration=duration,
                functions_found=functions_found,
                strings_found=strings_found,
                error=error,
                workspace=comp_ws_rel,
            )

        except Exception as exc:
            duration = time.monotonic() - start
            logger.warning(
                "  [FAIL] %s: %s (%.1fs)", name, exc, duration,
            )
            return ComponentResult(
                name=name,
                path=str(comp_path),
                component_type=comp_type,
                success=False,
                duration=duration,
                error=str(exc),
                workspace=comp_ws_rel,
            )
