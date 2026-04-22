"""Pipeline stage'leri -- identify, static, dynamic, deobfuscate, reconstruct, report.

Her stage Pipeline'a register edilerek calistirilir. Stage'ler
PipelineContext uzerinden hedef bilgilerine, workspace'e ve
onceki stage sonuclarina erisir.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES

from karadul.analyzers import get_analyzer
from karadul.core.pipeline import PipelineContext, Stage
from karadul.core.result import StageResult
from karadul.core.target import TargetDetector, TargetType, Language

# NameMerger opsiyonel -- import hatasi olursa None kalir
try:
    from karadul.reconstruction.name_merger import NameMerger, NamingCandidate
except ImportError:
    NameMerger = None  # type: ignore[misc,assignment]
    NamingCandidate = None  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)

# v1.9.2: Module-level constant -- her _execute_binary cagirisinda yeniden olusturulmaz.
from karadul.core.platform_map import TARGET_PLATFORM_MAP as _TARGET_PLATFORM_MAP


# ---------------------------------------------------------------------------
# Ortak yardimci fonksiyonlar (duplicate method'lar buraya cikarildi)
# ---------------------------------------------------------------------------

def _merge_stage_results(
    go_result: StageResult,
    binary_result: StageResult,
    start: float,
) -> StageResult:
    """Go + binary stage sonuclarini birlestir (v1.6.5 hybrid pipeline).

    Go-spesifik sonuclar korunur, binary sonuclar eklenir.
    Stats cakismalarinda Go verisi "go_" prefix ile korunur.
    """
    merged_stats = dict(go_result.stats)
    for k, v in binary_result.stats.items():
        if k in merged_stats:
            merged_stats["go_" + k] = merged_stats[k]
        merged_stats[k] = v

    merged_artifacts = dict(go_result.artifacts)
    for k, v in binary_result.artifacts.items():
        if k in merged_artifacts:
            merged_artifacts["go_" + k] = merged_artifacts[k]
        merged_artifacts[k] = v

    merged_errors = list(go_result.errors) + list(binary_result.errors)

    return StageResult(
        stage_name=go_result.stage_name,
        success=go_result.success or binary_result.success,
        duration_seconds=time.monotonic() - start,
        artifacts=merged_artifacts,
        stats=merged_stats,
        errors=merged_errors,
    )


def _collect_all_algorithms(algo_result, eng_result) -> list:
    """algo_result ve eng_result'tan algoritma listesini topla."""
    all_algos: list = []
    if algo_result and algo_result.success:
        all_algos.extend(algo_result.algorithms)
    if eng_result and eng_result.success:
        all_algos.extend(eng_result.algorithms)
    return all_algos


class IdentifyStage(Stage):
    """Hedef tanimlama stage'i.

    TargetDetector ile dosya tipini, dilini ve metadata'sini tespit eder.
    Sonucu context.target'a atar.
    """

    name = "identify"
    requires: tuple[str, ...] = ()

    def execute(self, context: PipelineContext) -> StageResult:
        """Hedef dosyayi taniy ve context'e yaz.

        Not: Pipeline.run() zaten target detection yapiyor ve context.target'i
        set ediyor. Bu stage ek metadata toplamak ve target_info'yu workspace'e
        kaydetmek icin kullanilir.
        """
        start = time.monotonic()
        errors: list[str] = []
        artifacts: dict = {}

        target = context.target

        # Target info'yu workspace'e kaydet
        try:
            target_path = context.workspace.save_json(
                "raw", "target_info", target.to_dict(),
            )
            artifacts["target_info"] = target_path
        except Exception as exc:
            errors.append(f"Target info kaydedilemedi: {exc}")

        stats = {
            "target_type": target.target_type.value,
            "language": target.language.value,
            "file_size": target.file_size,
            "bundler": target.metadata.get("bundler", "unknown"),
        }

        return StageResult(
            stage_name=self.name,
            success=True,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )


class StaticAnalysisStage(Stage):
    """Statik analiz stage'i.

    Hedef tipine uygun analyzer'i bulur ve analyze_static() cagistirir.
    """

    name = "static"
    requires = ["identify"]

    def execute(self, context: PipelineContext) -> StageResult:
        """Analyzer ile statik analiz calistir."""
        start = time.monotonic()

        target = context.target

        # APP_BUNDLE ise ozel akis: tum bilesenleri paralel analiz et
        if target.target_type == TargetType.APP_BUNDLE:
            return self._execute_app_bundle(context, start)

        # Uygun analyzer'i bul
        try:
            analyzer_cls = get_analyzer(target.target_type)
        except ValueError as exc:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"Analyzer bulunamadi: {exc}"],
            )

        # Analyzer instance olustur
        analyzer = analyzer_cls(context.config)

        # Statik analiz calistir
        context.report_progress("Running static analysis...", 0.1)
        try:
            result = analyzer.analyze_static(target, context.workspace)
            context.report_progress("Static analysis complete", 0.7)
        except Exception as exc:
            logger.exception("Statik analiz hatasi: %s", exc)
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

        # v1.6.5: Go binary hybrid pipeline — Go analyzer Ghidra calistirmiyor.
        # Downstream reconstruct stage decompiled C dosyalarina bagimli.
        # MachOAnalyzer uzerinden Ghidra'yi da calistir, sonuclari merge et.
        if target.target_type == TargetType.GO_BINARY:
            try:
                from karadul.analyzers.macho import MachOAnalyzer
                ghidra_analyzer = MachOAnalyzer(context.config)
                if ghidra_analyzer.ghidra.is_available():
                    context.report_progress("Go hybrid: running Ghidra decompilation...", 0.5)
                    ghidra_result = ghidra_analyzer._run_ghidra(
                        target.path, context.workspace,
                    )
                    if ghidra_result and ghidra_result.get("success"):
                        # Ghidra ciktilarini ayni workspace'e kaydet
                        for script_name, output in ghidra_result.get(
                            "scripts_output", {},
                        ).items():
                            ghidra_art_path = context.workspace.save_json(
                                "static", "ghidra_%s" % script_name, output,
                            )
                            result.artifacts["ghidra_%s" % script_name] = ghidra_art_path
                        result.stats["ghidra_success"] = True
                        result.stats["ghidra_duration"] = ghidra_result.get(
                            "duration_seconds", 0,
                        )
                        combined = ghidra_result.get("scripts_output", {}).get(
                            "combined_results", {},
                        )
                        if combined:
                            summary = combined.get("summary", {})
                            result.stats["ghidra_function_count"] = summary.get(
                                "function_count", 0,
                            )
                            result.stats["ghidra_decompiled"] = summary.get(
                                "decompiled_success", 0,
                            )
                        logger.info(
                            "Go hybrid: Ghidra decompilation tamamlandi "
                            "(%.1fs)",
                            ghidra_result.get("duration_seconds", 0),
                        )
                    else:
                        result.stats["ghidra_success"] = False
                        logger.warning("Go hybrid: Ghidra analiz basarisiz")
                else:
                    result.stats["ghidra_available"] = False
                    logger.info("Go hybrid: Ghidra mevcut degil, atlaniyor")
            except ImportError:
                logger.debug("Go hybrid: MachOAnalyzer import edilemedi")
            except Exception as exc:
                logger.warning("Go hybrid Ghidra hatasi (atlaniyor): %s", exc)

        # v1.8.0: Bun compiled binary — __BUN segmentinden JS extraction
        if target.target_type == TargetType.BUN_BINARY:
            try:
                from karadul.analyzers.macho import MachOAnalyzer as _MachOAnalyzer
                bun_analyzer = _MachOAnalyzer(context.config)
                context.report_progress("BUN: extracting embedded JS...", 0.6)
                bun_js_path = bun_analyzer._extract_bun_js(
                    target.path, context.workspace,
                )
                if bun_js_path is not None:
                    result.artifacts["bun_bundle_js"] = bun_js_path
                    result.stats["bun_js_extracted"] = True
                    result.stats["bun_js_size"] = bun_js_path.stat().st_size
                    logger.info(
                        "BUN segment detected: %d bytes JS extracted",
                        result.stats["bun_js_size"],
                    )
                else:
                    result.stats["bun_js_extracted"] = False
                    logger.warning("BUN: JS extraction basarisiz")
            except ImportError:
                logger.debug("BUN: MachOAnalyzer import edilemedi")
            except Exception as exc:
                logger.warning("BUN JS extraction hatasi (atlaniyor): %s", exc)

        # YARA taramasi -- binary hedefler icin opsiyonel pattern tarama
        context.report_progress("YARA pattern scanning...", 0.8)
        try:
            from karadul.analyzers.yara_scanner import YaraScanner
            scanner = YaraScanner()
            scanner.load_builtin_rules()
            yara_result = scanner.scan_file(target.path)
            if yara_result.matches:
                result.stats["yara_matches"] = len(yara_result.matches)
                result.stats["yara_scan_time_ms"] = yara_result.scan_time_ms
                result.stats["yara_backend"] = yara_result.backend
                for m in yara_result.matches:
                    tags_str = ",".join(m.tags) if m.tags else "unknown"
                    result.stats.setdefault("detected_tech", []).append(
                        f"{m.rule} ({tags_str})"
                    )
                logger.info(
                    "YARA: %d kural eslesti (%s backend, %.1fms)",
                    len(yara_result.matches), yara_result.backend,
                    yara_result.scan_time_ms,
                )
        except ImportError:
            logger.debug("YaraScanner bulunamadi, atlaniyor")
        except Exception as exc:
            logger.warning("YARA tarama hatasi (atlaniyor): %s", exc)

        # v1.8.6: CAPA capability detection -- binary hedefler icin
        if (
            context.config.binary_reconstruction.enable_capa
            and target.target_type in (
                TargetType.MACHO_BINARY, TargetType.UNIVERSAL_BINARY,
                TargetType.ELF_BINARY, TargetType.PE_BINARY, TargetType.GO_BINARY,
                TargetType.BUN_BINARY,
            )
        ):
            context.report_progress("CAPA capability detection...", 0.85)
            try:
                from karadul.analyzers.capa_scanner import CAPAScanner

                _capa_rules = context.config.binary_reconstruction.capa_rules_path or None
                _capa_timeout = context.config.binary_reconstruction.capa_timeout
                capa_scanner = CAPAScanner(
                    rules_path=_capa_rules,
                    timeout=_capa_timeout,
                )
                if capa_scanner.is_available():
                    capa_result = capa_scanner.scan(target.path)
                    if capa_result.success:
                        result.stats["capa_rules_matched"] = capa_result.total_rules_matched
                        result.stats["capa_functions_matched"] = capa_result.total_functions_matched
                        result.stats["capa_file_capabilities"] = len(capa_result.file_capabilities)
                        result.stats["capa_duration"] = round(capa_result.duration_seconds, 1)
                        # Sonuclari workspace'e kaydet (reconstruction kullanacak)
                        context.workspace.save_json(
                            "static", "capa_capabilities", capa_result.to_dict(),
                        )
                        logger.info(
                            "CAPA: %d kural eslesti, %d fonksiyonda capability "
                            "(%.1fs, format=%s)",
                            capa_result.total_rules_matched,
                            capa_result.total_functions_matched,
                            capa_result.duration_seconds,
                            capa_result.format_,
                        )
                    elif capa_result.errors:
                        logger.debug("CAPA scan basarisiz: %s", capa_result.errors[0])
                else:
                    logger.debug("CAPA mevcut degil, atlaniyor")
            except ImportError:
                logger.debug("flare-capa kurulu degil, CAPA atlaniyor")
            except Exception as exc:
                logger.warning("CAPA scan hatasi (atlaniyor): %s", exc)

        # FLIRT byte pattern matching -- binary hedefler icin kutuphane fonksiyon tanima
        if target.target_type in (
            TargetType.MACHO_BINARY, TargetType.UNIVERSAL_BINARY,
            TargetType.ELF_BINARY, TargetType.PE_BINARY, TargetType.GO_BINARY,
            TargetType.BUN_BINARY,
        ):
            try:
                from karadul.analyzers.flirt_parser import FLIRTParser

                fp = FLIRTParser()
                all_flirt_sigs = []

                # 1. Homebrew signature'larini yukle (proje kokunde)
                project_root = context.config.project_root
                homebrew_sigs = project_root / "signatures_homebrew.json"
                if homebrew_sigs.exists():
                    sigs = fp.load_json_signatures(homebrew_sigs)
                    all_flirt_sigs.extend(sigs)
                    logger.debug("FLIRT: Homebrew sigs: %d", len(sigs))

                # 2. macOS framework signature'larini yukle (sigs/ dizini)
                sigs_dir = project_root / "sigs"
                if sigs_dir.is_dir():
                    sigs = fp.load_directory(sigs_dir)
                    all_flirt_sigs.extend(sigs)
                    logger.debug("FLIRT: sigs/ dizini: %d", len(sigs))

                # 3. Config'teki external signature path'leri
                ext_paths = context.config.binary_reconstruction.external_signature_paths
                if ext_paths:
                    for ext_path in ext_paths:
                        p = Path(ext_path)
                        if p.is_file() and p.suffix == ".json":
                            sigs = fp.load_json_signatures(p)
                            all_flirt_sigs.extend(sigs)
                        elif p.is_file() and p.suffix == ".pat":
                            sigs = fp.load_pat_file(p)
                            all_flirt_sigs.extend(sigs)
                        elif p.is_dir():
                            sigs = fp.load_directory(p)
                            all_flirt_sigs.extend(sigs)

                # 4. Binary'den dogrudan symbol extraction
                binary_sigs = fp.extract_from_binary(target.path)
                all_flirt_sigs.extend(binary_sigs)

                # FLIRT sonuclarini stats'a kaydet
                result.stats["flirt_signatures_loaded"] = len(all_flirt_sigs)
                result.stats["flirt_binary_symbols"] = len(binary_sigs)

                if all_flirt_sigs:
                    # Byte pattern'li signature'larin sayisini logla
                    byte_pattern_count = sum(
                        1 for s in all_flirt_sigs if s.byte_pattern
                    )
                    result.stats["flirt_byte_patterns"] = byte_pattern_count
                    logger.info(
                        "FLIRT: %d signature yuklendi (%d byte pattern, %d binary symbol)",
                        len(all_flirt_sigs), byte_pattern_count, len(binary_sigs),
                    )

                    # Signature'lari workspace'e kaydet (ReconstructionStage kullanabilir)
                    try:
                        flirt_data = {
                            "total": len(all_flirt_sigs),
                            "byte_patterns": byte_pattern_count,
                            "binary_symbols": len(binary_sigs),
                            "signatures": [s.to_dict() for s in all_flirt_sigs[:5000]],
                        }
                        context.workspace.save_json("static", "flirt_signatures", flirt_data)
                    except Exception:
                        logger.debug("FLIRT signature kaydi basarisiz, atlaniyor", exc_info=True)

            except ImportError:
                logger.debug("FLIRTParser bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("FLIRT matching hatasi (atlaniyor): %s", exc)

        # Stage name'i zorla ayarla (analyzer farkli isim vermis olabilir)
        result.stage_name = self.name
        return result

    def _execute_app_bundle(
        self, context: PipelineContext, start: float,
    ) -> StageResult:
        """APP_BUNDLE icin ozel statik analiz akisi.

        AppBundleAnalyzer ile tum bilesenleri (binary, JAR, framework, Electron)
        paralel analiz eder. En cok fonksiyonu olan basarili bileseni
        'ana hedef' olarak isaretler (downstream stage'ler icin).
        """
        from karadul.analyzers.app_bundle import AppBundleAnalyzer

        target = context.target
        stats: dict = {}

        try:
            analyzer = AppBundleAnalyzer(context.config)
            bundle_result = analyzer.analyze_static(target, context.workspace)
        except Exception as exc:
            logger.exception("App Bundle analiz hatasi: %s", exc)
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

        # Bundle istatistikleri
        stats["bundle_components"] = bundle_result.total_components
        stats["bundle_analyzed"] = bundle_result.analyzed_components
        stats["bundle_failed"] = bundle_result.failed_components
        stats["bundle_functions"] = bundle_result.total_functions
        stats["bundle_strings"] = bundle_result.total_strings
        stats["target_type"] = "app_bundle"

        # En buyuk binary'yi "ana hedef" olarak isaretle (downstream icin)
        successful = [r for r in bundle_result.component_results if r.success]
        if successful:
            main_comp = max(successful, key=lambda r: r.functions_found)
            context.metadata["main_component"] = main_comp.path
            context.metadata["main_component_type"] = main_comp.component_type
            stats["main_component"] = main_comp.name
            stats["main_component_functions"] = main_comp.functions_found

        return StageResult(
            stage_name=self.name,
            success=bundle_result.success,
            duration_seconds=time.monotonic() - start,
            artifacts={},
            stats=stats,
            errors=[
                f"{r.name}: {r.error}"
                for r in bundle_result.component_results
                if not r.success and r.error
            ],
        )


class DynamicAnalysisStage(Stage):
    """Dinamik analiz stage'i -- Frida ile runtime izleme.

    Hedef tipine gore uygun hook script'i secer (nodejs, objc, generic),
    process'i spawn veya attach eder, belirli sure veri toplar,
    FunctionTracer ile analiz eder ve sonuclari workspace/dynamic/ altina kaydeder.

    Frida kurulu degilse veya SIP kisitlamasi varsa graceful skip yapar.
    """

    name = "dynamic"
    requires = ["identify"]  # static'ten bagimsiz calisabilir

    def execute(self, context: PipelineContext) -> StageResult:
        """Frida ile dinamik analiz calistir."""
        start = time.monotonic()
        errors: list[str] = []
        artifacts: dict[str, Path] = {}
        stats: dict = {}

        # Frida import kontrolu
        try:
            from karadul.frida.session import FridaSession, FridaNotAvailableError, FridaAttachError
            from karadul.frida.collectors.function_tracer import FunctionTracer
        except ImportError as exc:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"Frida modulleri yuklenemedi: {exc}"],
            )

        # FridaSession olustur
        try:
            session = FridaSession(context.config)
        except FridaNotAvailableError as exc:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[str(exc)],
            )

        target = context.target
        hooks_dir = Path(__file__).parent / "frida" / "hooks"

        # Hedef tipine gore hook script sec
        hook_script = self._select_hook_script(target, hooks_dir)
        if hook_script and not hook_script.exists():
            errors.append(f"Hook script bulunamadi: {hook_script}")
            hook_script = None

        try:
            # Spawn veya attach karari
            target_path = str(target.path)

            if target.target_type in (TargetType.JS_BUNDLE,):
                # JS bundle: node ile spawn et
                node_path = str(context.config.tools.node)
                pid = session.spawn(node_path, args=[target_path])
                stats["spawn_method"] = "node_spawn"
            elif target.target_type in (
                TargetType.MACHO_BINARY, TargetType.UNIVERSAL_BINARY,
                TargetType.GO_BINARY,
                TargetType.ELF_BINARY, TargetType.PE_BINARY,
            ):
                # Native binary: dogrudan spawn et
                pid = session.spawn(target_path)
                stats["spawn_method"] = "direct_spawn"
            elif target.target_type == TargetType.ELECTRON_APP:
                # Electron: ana binary'yi spawn et
                main_binary = target.metadata.get("main_binary")
                if main_binary:
                    pid = session.spawn(main_binary)
                else:
                    pid = session.spawn(target_path)
                stats["spawn_method"] = "electron_spawn"
            else:
                # Bilinmeyen tip: dogrudan spawn dene
                pid = session.spawn(target_path)
                stats["spawn_method"] = "generic_spawn"

            stats["pid"] = pid

            # Hook script yukle
            if hook_script:
                session.load_script(hook_script)
                stats["hook_script"] = hook_script.name
            else:
                # Generic hooks her zaman yukle
                generic_hook = hooks_dir / "generic_hooks.js"
                if generic_hook.exists():
                    session.load_script(generic_hook)
                    stats["hook_script"] = "generic_hooks.js"

            # Veri toplama suresi
            collect_timeout = float(context.config.timeouts.frida_attach)
            session.wait(timeout=collect_timeout)
            stats["collect_duration"] = collect_timeout

            # Mesajlari topla
            messages = session.messages
            frida_errors = session.errors
            stats["total_messages"] = len(messages)
            stats["total_errors"] = len(frida_errors)

            # FunctionTracer ile analiz
            tracer = FunctionTracer()
            tracer.process_messages(messages)

            trace_report = tracer.to_json()
            stats["unique_modules"] = len(trace_report.get("unique_modules", []))
            stats["api_calls"] = len(trace_report.get("api_calls", []))
            stats["file_accesses"] = len(trace_report.get("file_accesses", []))
            stats["crypto_operations"] = len(trace_report.get("crypto_operations", []))
            stats["call_stats"] = trace_report.get("stats", {})

            # Sonuclari workspace'e kaydet
            dynamic_dir = context.workspace.get_stage_dir("dynamic")

            # Ana rapor
            report_path = context.workspace.save_json("dynamic", "trace_report", trace_report)
            artifacts["trace_report"] = report_path

            # Ham mesajlar
            raw_path = context.workspace.save_json(
                "dynamic", "raw_messages",
                {"messages": messages, "errors": frida_errors},
            )
            artifacts["raw_messages"] = raw_path

            # Frida hatalari varsa logla
            if frida_errors:
                for err in frida_errors[:5]:
                    desc = err.get("description", str(err))
                    errors.append(f"Frida script hatasi: {desc}")

            success = True

        except FridaAttachError as exc:
            errors.append(f"Frida attach/spawn hatasi: {exc}")
            success = False

        except Exception as exc:
            errors.append(f"Dinamik analiz hatasi: {type(exc).__name__}: {exc}")
            logger.exception("DynamicAnalysisStage exception")
            success = False

        finally:
            # Session'i her zaman kapat
            try:
                session.detach()
            except Exception:
                logger.debug("Frida session detach basarisiz, atlaniyor", exc_info=True)

        # Debugger Bridge: runtime deger yakalama (opsiyonel, v1.2.9+)
        if context.config.debugger.enabled:
            try:
                from karadul.ghidra.debugger_bridge import DebuggerBridge
                bridge = DebuggerBridge(context.config)
                debugger_type = bridge.detect_debugger()
                if debugger_type:
                    stats["debugger_type"] = debugger_type
                    stats["debugger_enabled"] = True
                    logger.info("Debugger bridge: %s tespit edildi", debugger_type)
                else:
                    stats["debugger_enabled"] = False
                    logger.info("Debugger bulunamadi (lldb/gdb), atlaniyor")
            except ImportError:
                logger.debug("DebuggerBridge bulunamadi, atlaniyor")
            except Exception as exc:
                errors.append(f"Debugger bridge hatasi: {exc}")

        return StageResult(
            stage_name=self.name,
            success=success,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    @staticmethod
    def _select_hook_script(target, hooks_dir: Path) -> Path | None:
        """Hedef tipine gore uygun hook script'ini sec.

        Args:
            target: TargetInfo instance'i.
            hooks_dir: Hook scriptlerinin bulundugu dizin.

        Returns:
            Hook script yolu veya None.
        """
        if target.language == Language.JAVASCRIPT:
            return hooks_dir / "nodejs_hooks.js"
        elif target.language == Language.OBJECTIVE_C:
            return hooks_dir / "objc_hooks.js"
        elif target.language == Language.SWIFT:
            # Swift uygulamalari ObjC runtime'i da kullanir
            return hooks_dir / "objc_hooks.js"
        else:
            return hooks_dir / "generic_hooks.js"


class DeobfuscationStage(Stage):
    """Deobfuscation stage'i.

    Iki mod:
    1. use_deep=True (default): DeepDeobfuscationPipeline -- 9 phase Babel transform + akilli modul cikarma
    2. use_deep=False: Analyzer'in deobfuscate() -- beautify + synchrony + babel + webpack unpack

    Not: ``requires`` listesi kasitli olarak ["identify"] yapildi (eskiden ["static"]).
    Static analiz basarisiz olsa bile (orn. Babel parse hatasi) deobfuscation
    devam edebilmelidir -- deobfuscation kendi icerisinde beautify + Babel/Acorn
    fallback kullaniyor.
    """

    name = "deobfuscate"
    requires = ["identify"]

    def __init__(self, *, use_deep: bool = True) -> None:
        self._use_deep = use_deep

    def execute(self, context: PipelineContext) -> StageResult:
        """Deobfuscation calistir."""
        start = time.monotonic()

        # Binary hedefler icin binary deobfuscation pipeline
        target = context.target

        # v1.6.5: Go binary hybrid pipeline — Go deobfuscation ONCE,
        # sonra binary deobfuscation (Ghidra ciktisini temizle) de calistir.
        if target.target_type == TargetType.GO_BINARY:
            go_result = self._execute_go_binary(context, start)
            # Binary deobfuscation da calistir (Ghidra temizligi)
            try:
                binary_result = self._execute_binary(context, start)
                return self._merge_stage_results(go_result, binary_result, start)
            except Exception as exc:
                logger.warning(
                    "Go hybrid deobfuscation: binary deobf basarisiz (%s), "
                    "sadece Go sonucu donuluyor",
                    exc,
                )
                return go_result

        if target.target_type in (
            TargetType.MACHO_BINARY,
            TargetType.UNIVERSAL_BINARY,
            TargetType.ELF_BINARY,
            TargetType.PE_BINARY,
            TargetType.BUN_BINARY,      # v1.9.1: Bun native kodu da reconstruction'a girmeli
            TargetType.DELPHI_BINARY,   # v1.9.1: PE-based native binary
        ):
            return self._execute_binary(context, start)

        if self._use_deep:
            return self._execute_deep(context, start)
        else:
            return self._execute_legacy(context, start)

    def _execute_go_binary(self, context: PipelineContext, start: float) -> StageResult:
        """Go binary deobfuscation — GOPCLNTAB zaten orijinal isimleri iceriyor."""
        try:
            analyzer_cls = get_analyzer(context.target.target_type)
            analyzer = analyzer_cls(context.config)
            result = analyzer.deobfuscate(context.target, context.workspace)
        except Exception as exc:
            logger.exception("Go binary deobfuscation hatasi: %s", exc)
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"{type(exc).__name__}: {exc}"],
            )
        result.stage_name = self.name
        return result

    def _execute_binary(self, context: PipelineContext, start: float) -> StageResult:
        """Binary deobfuscation — Ghidra ciktisini temizle ve isle."""
        from karadul.deobfuscators.binary_deobfuscator import BinaryDeobfuscator

        deobfuscator = BinaryDeobfuscator(context.config)

        try:
            result = deobfuscator.deobfuscate(context.workspace)
        except Exception as exc:
            logger.exception("Binary deobfuscation hatasi: %s", exc)
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

        return StageResult(
            stage_name=self.name,
            success=result.success,
            duration_seconds=time.monotonic() - start,
            artifacts=result.artifacts,
            stats=result.stats,
            errors=result.errors,
        )

    @staticmethod
    def _merge_stage_results(
        go_result: StageResult,
        binary_result: StageResult,
        start: float,
    ) -> StageResult:
        return _merge_stage_results(go_result, binary_result, start)

    def _resolve_deob_input(self, context: PipelineContext) -> Path:
        """Deobfuscation icin dogru girdi dosyasini bul.

        Electron uygulamalari icin extract edilmis ana JS dosyasini kullanir.
        JS bundle'lar icin dogrudan target.path'i dondurur.
        """
        target = context.target

        # Electron uygulamalari: ASAR arsiv, JS olarak parse edilemez
        # Static stage'in extract ettigi JS dosyalarini kullan
        if target.target_type == TargetType.ELECTRON_APP:
            # 1. Static stage'den main_js bilgisini al
            if "static" in context.results:
                static_stats = context.results["static"].stats
                main_js_str = static_stats.get("main_js")
                if main_js_str:
                    main_js = Path(main_js_str)
                    if main_js.exists():
                        logger.info(
                            "Electron deob: static stage'den main_js kullaniliyor: %s",
                            main_js,
                        )
                        return main_js

                # 2. Extract dizinindeki en buyuk JS dosyasini bul
                asar_extracted = context.workspace.get_stage_dir("raw") / "asar_extracted"
                if asar_extracted.exists():
                    js_files = sorted(
                        asar_extracted.rglob("*.js"),
                        key=lambda f: f.stat().st_size,
                        reverse=True,
                    )
                    # node_modules'i atla
                    for js_file in js_files:
                        rel_parts = js_file.relative_to(asar_extracted).parts
                        if "node_modules" not in rel_parts:
                            logger.info(
                                "Electron deob: en buyuk JS kullaniliyor: %s (%d bytes)",
                                js_file, js_file.stat().st_size,
                            )
                            return js_file

            logger.warning(
                "Electron deob: extract edilmis JS bulunamadi, orijinal path deneniyor"
            )

        return target.path

    def _execute_deep(self, context: PipelineContext, start: float) -> StageResult:
        """DeepDeobfuscationPipeline ile gelismis deobfuscation."""
        from karadul.deobfuscators.deep_pipeline import DeepDeobfuscationPipeline

        pipeline = DeepDeobfuscationPipeline(context.config)

        # Electron icin extract edilmis JS'i bul, JS bundle icin dogrudan path
        input_file = self._resolve_deob_input(context)

        try:
            result = pipeline.run(
                input_file,
                context.workspace,
            )
        except Exception as exc:
            logger.exception("Deep deobfuscation hatasi: %s", exc)
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

        # DeepDeobfuscationResult -> StageResult donusumu
        artifacts = {}
        if result.output_file:
            artifacts["output_file"] = result.output_file
        if result.modules_dir:
            artifacts["modules_dir"] = result.modules_dir

        errors = []
        for step_name, step_info in result.steps.items():
            step_errors = step_info.get("errors", [])
            if isinstance(step_errors, list):
                errors.extend(step_errors)
            if not step_info.get("success") and step_info.get("error"):
                errors.append(f"{step_name}: {step_info['error']}")

        return StageResult(
            stage_name=self.name,
            success=result.success,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            stats={
                "total_modules": result.total_modules,
                "bundle_format": result.bundle_format,
                "steps": result.steps,
                **result.stats,
            },
            errors=errors,
        )

    def _execute_legacy(self, context: PipelineContext, start: float) -> StageResult:
        """Eski yontem: Analyzer.deobfuscate()."""
        target = context.target

        try:
            analyzer_cls = get_analyzer(target.target_type)
        except ValueError as exc:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"Analyzer bulunamadi: {exc}"],
            )

        analyzer = analyzer_cls(context.config)

        try:
            result = analyzer.deobfuscate(target, context.workspace)
        except Exception as exc:
            logger.exception("Deobfuscation hatasi: %s", exc)
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

        result.stage_name = self.name
        return result


class ReconstructionStage(Stage):
    """Kod rekonstruksiyonu stage'i -- calistiriilabilir proje ureti.

    Pipeline sirasina gore:
    1. ContextNamer ile degiskenleri yeniden adlandir (300+ kural)
    1.5. LLM-Assisted naming (opsiyonel)
    1.8. ParamRecovery ile fonksiyon parametrelerini kurtar (5 strateji)
    2. ModuleSplitter ile webpack modullerini kategorize et
    2.5. NamingPipeline ile modulleri isimlendir (npm fingerprint + structural + heuristic)
    3. TypeInferrer ile JSDoc tip yorumlari ekle
    4. CommentGenerator ile fonksiyon yorumlari ekle
    5. GapFiller ile eksikleri tamamla
    6. ProjectReconstructor ile gercek proje yapisi olustur (10+ modul varsa)
       VEYA ProjectBuilder ile basit proje uret (az modul varsa)

    Sonuclari workspace/reconstructed/ altina kaydeder.
    """

    name = "reconstruct"
    requires = ["identify"]  # v1.9.1: deobfuscate -> identify (native binary'de deobf gereksiz)

    def __init__(self, *, use_project_reconstructor: bool = True) -> None:
        self._use_project_reconstructor = use_project_reconstructor

    def execute(self, context: PipelineContext) -> StageResult:
        """Tam reconstruction pipeline'i calistir."""
        start = time.monotonic()

        # Hedef tipine gore reconstruction yontem sec
        target = context.target

        # APP_BUNDLE: her bilesen icin ayri reconstruction
        if target.target_type == TargetType.APP_BUNDLE:
            return self._execute_app_bundle(context, start)

        # v1.6.5: Go binary hybrid pipeline — Go reconstruction ONCE,
        # sonra full binary reconstruction (Ghidra + compute) de calistir.
        if target.target_type == TargetType.GO_BINARY:
            go_result = self._execute_go_binary(context, start)
            # Binary reconstruction da calistir (Ghidra decompile + compute)
            try:
                binary_result = self._execute_binary(context, start)
                return self._merge_stage_results(go_result, binary_result, start)
            except Exception as exc:
                logger.warning(
                    "Go hybrid reconstruction: binary recon basarisiz (%s), "
                    "sadece Go sonucu donuluyor",
                    exc,
                )
                return go_result

        # Binary hedefler icin C reconstruction pipeline
        if target.target_type in (
            TargetType.MACHO_BINARY,
            TargetType.UNIVERSAL_BINARY,
            TargetType.ELF_BINARY,
            TargetType.PE_BINARY,
            TargetType.BUN_BINARY,      # v1.9.1: Bun native kodu
            TargetType.DELPHI_BINARY,   # v1.9.1: PE-based native
        ):
            return self._execute_binary(context, start)

        return self._execute_js(context, start)

    def _execute_app_bundle(self, context: PipelineContext, start: float) -> StageResult:
        """APP_BUNDLE reconstruction — her bilesen icin uygun reconstruction calistir.

        StaticAnalysisStage'deki bundle_analysis sonucunu okur,
        basarili her bilesen icin bilesen tipine gore reconstruction yapar.
        Ana bilesen (en cok fonksiyonu olan) icin tam reconstruction,
        digerleri icin ozet reconstruction uygular.
        """
        from karadul.analyzers.app_bundle import AppBundleAnalyzer

        errors: list[str] = []
        stats: dict = {}
        artifacts: dict[str, Path] = {}
        target = context.target

        # Static stage'deki bundle analiz sonucunu oku
        try:
            bundle_data = context.workspace.load_json("static", "bundle_analysis")
        except Exception:
            logger.debug("Bundle analysis JSON yuklenemedi, atlaniyor", exc_info=True)
            bundle_data = None

        if not bundle_data:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=["Bundle analiz sonucu bulunamadi (static stage basarisiz mi?)"],
            )

        component_results = bundle_data.get("component_results", [])
        successful_components = [c for c in component_results if c.get("success")]

        if not successful_components:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=["Basarili bilesen yok, reconstruction yapilamaz"],
            )

        # Ana bilesen: en cok fonksiyonu olan
        main_comp = max(successful_components, key=lambda c: c.get("functions", 0))
        main_comp_path = context.metadata.get("main_component", main_comp.get("path", ""))

        stats["bundle_name"] = bundle_data.get("bundle_name", "")
        stats["total_components"] = len(component_results)
        stats["reconstructed_components"] = 0
        stats["main_component"] = main_comp.get("name", "")

        # Ana bilesen icin tam reconstruction: uygun _execute_* metoduna yonlendir
        if main_comp_path:
            main_type = context.metadata.get(
                "main_component_type",
                main_comp.get("type", "macho_binary"),
            )

            # Ana bilesen tipine gore reconstruction metodu sec
            if main_type in ("macho_binary", "universal_binary", "elf_binary", "pe_binary"):
                try:
                    result = self._execute_binary(context, start)
                    stats["reconstructed_components"] += 1
                    stats["main_reconstruction"] = "binary"
                    # Binary reconstruction sonuclarini merge et
                    stats.update({
                        k: v for k, v in result.stats.items()
                        if k not in stats
                    })
                    errors.extend(result.errors)
                    artifacts.update(result.artifacts)
                except Exception as exc:
                    errors.append(f"Ana bilesen reconstruction hatasi: {exc}")
            elif main_type == "go_binary":
                # v1.6.5: Go binary hybrid pipeline — bundle icinde de
                # Go + binary reconstruction birlikte calistir
                try:
                    go_result = self._execute_go_binary(context, start)
                    stats["reconstructed_components"] += 1
                    stats["main_reconstruction"] = "go_hybrid"
                    stats.update({
                        k: v for k, v in go_result.stats.items()
                        if k not in stats
                    })
                    errors.extend(go_result.errors)
                    artifacts.update(go_result.artifacts)
                    # Binary reconstruction da calistir
                    try:
                        bin_result = self._execute_binary(context, start)
                        stats.update({
                            k: v for k, v in bin_result.stats.items()
                            if k not in stats
                        })
                        errors.extend(bin_result.errors)
                        artifacts.update(bin_result.artifacts)
                        stats["reconstructed_components"] += 1
                    except Exception as exc:
                        logger.warning(
                            "Go hybrid bundle: binary recon basarisiz: %s", exc,
                        )
                except Exception as exc:
                    errors.append(f"Go bilesen reconstruction hatasi: {exc}")
            elif main_type in ("electron_app", "js_bundle"):
                try:
                    result = self._execute_js(context, start)
                    stats["reconstructed_components"] += 1
                    stats["main_reconstruction"] = "js"
                    stats.update({
                        k: v for k, v in result.stats.items()
                        if k not in stats
                    })
                    errors.extend(result.errors)
                    artifacts.update(result.artifacts)
                except Exception as exc:
                    errors.append(f"JS bilesen reconstruction hatasi: {exc}")
            else:
                errors.append(f"Bilinmeyen bilesen tipi: {main_type}")

        logger.info(
            "Bundle reconstruction: %d/%d bilesen, ana=%s",
            stats.get("reconstructed_components", 0),
            len(successful_components),
            stats.get("main_component", "?"),
        )

        return StageResult(
            stage_name=self.name,
            success=stats.get("reconstructed_components", 0) > 0,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    @staticmethod
    def _merge_stage_results(
        go_result: StageResult,
        binary_result: StageResult,
        start: float,
    ) -> StageResult:
        return _merge_stage_results(go_result, binary_result, start)

    def _execute_go_binary(self, context: PipelineContext, start: float) -> StageResult:
        """Go binary reconstruction — GoBinaryAnalyzer.reconstruct() ile."""
        try:
            analyzer_cls = get_analyzer(context.target.target_type)
            analyzer = analyzer_cls(context.config)
            result = analyzer.reconstruct(context.target, context.workspace)
        except Exception as exc:
            logger.exception("Go reconstruction hatasi: %s", exc)
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"{type(exc).__name__}: {exc}"],
            )
        if result is None:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=["Go reconstruction sonuc dondurmedi"],
            )
        result.stage_name = self.name
        return result

    def _execute_binary(self, context: PipelineContext, start: float) -> StageResult:
        """Binary reconstruction — decompile edilmis C'yi okunabilir yap."""
        errors: list[str] = []
        artifacts: dict[str, Path] = {}
        stats: dict = {}

        target = context.target
        static_dir = context.workspace.get_stage_dir("static")
        deob_dir = context.workspace.get_stage_dir("deobfuscated")
        reconstructed_dir = context.workspace.get_stage_dir("reconstructed")

        # v1.10.0 M1 T3.5: step registry shim. Feature flag False default.
        # True ise karadul.pipeline.runner uzerinden Phase 1 (8 step): T3.2'nin
        # 7 step'i + assembly_analysis. Downstream kod (L1910+ feedback loop +
        # struct_recovery) ayni local degiskenleri bekledigi icin artifact'lari
        # buradan geri aliriz. Phase 2 (feedback_loop + struct_recovery) eski
        # yolda kalir. Phase 3 (10 post-step) post-loop yerine runner2 uzerinden
        # calisir ve early return ile StageResult doner.
        _use_step_registry = bool(
            getattr(context.config, "pipeline", None)
            and context.config.pipeline.use_step_registry
        )
        if _use_step_registry:
            from karadul.pipeline.runner import PipelineRunner
            try:
                # v1.10.0 M4 entegrasyon: computation paketleri Phase 1'e
                # eklendi.
                #   - cfg_iso_match -- pcode_cfg_analysis'dan sonra
                #   - computation_fusion -- sig_matches + cfg_iso_matches
                #     hazir olunca (confidence_filter'dan sonra, assembly'den once)
                # Feature flag'ler step icinde kontrol edilir; kapaliyken noop.
                runner = PipelineRunner(steps=[
                    "binary_prep",
                    "ghidra_metadata",
                    # v1.11.0 Hafta 1: BSim SHADOW MODE — ghidra_metadata
                    # sonrasi (bsim_matches.json resolve edilebilsin),
                    # byte_pattern oncesi. Fusion'a/NameMerger'a YAZMAZ,
                    # sadece bsim_shadow.json dump eder.
                    "bsim_match",
                    "byte_pattern",
                    "pcode_cfg_analysis",
                    "cfg_iso_match",
                    "algorithm_id",
                    "parallel_algo_eng",
                    "confidence_filter",
                    "computation_fusion",
                    "assembly_analysis",
                ])
                step_ctx = runner.run(context)
            except RuntimeError as exc:
                return StageResult(
                    stage_name=self.name,
                    success=False,
                    duration_seconds=time.monotonic() - start,
                    errors=[str(exc)],
                )

            _a = step_ctx.artifacts
            # binary_prep
            binary_for_byte_match = _a["binary_for_byte_match"]
            c_files = _a["c_files"]
            _file_cache = _a["file_cache"]
            decompiled_dir = _a["decompiled_dir"]
            # ghidra_metadata — JSON path'leri
            functions_json = _a["functions_json_path"]
            strings_json = _a["strings_json_path"]
            call_graph_json = _a["call_graph_json_path"]
            ghidra_types_json = _a["ghidra_types_json_path"]
            xrefs_json = _a["xrefs_json_path"]
            pcode_json = _a["pcode_json_path"]
            cfg_json = _a["cfg_json_path"]
            fid_json = _a["fid_json_path"]
            decompiled_json = _a["decompiled_json_path"]
            output_dir = _a["output_dir"]
            # ghidra_metadata — parse cache + signature DB
            _func_data = _a["functions_data"]
            _string_data = _a["strings_data"]
            _call_graph_data = _a["call_graph_data"]
            sig_matches = _a["sig_matches"]
            # byte_pattern
            byte_pattern_names = _a["byte_pattern_names"]
            # pcode_cfg_analysis
            _pcode_result = _a["pcode_result"]
            _cfg_result = _a["cfg_result"]
            _pcode_naming_candidates = _a["pcode_naming_candidates"]
            # algorithm_id + parallel_algo_eng -> confidence_filter bunlari
            # filtered artifact olarak tekrar expose eder.
            algo_result = _a["algo_result_filtered"]
            eng_result = _a["eng_result_filtered"]
            extracted_names = _a["extracted_names"]
            calibrated_matches = _a["calibrated_matches"]
            _capa_capabilities = _a["capa_capabilities"]

            # stats/errors/artifacts merge — step'lerin biriktirdigi.
            stats.update(step_ctx.stats)
            errors.extend(step_ctx.errors)
            _pending = (context.metadata or {}).get("artifacts_pending", {})
            if _pending:
                artifacts.update(_pending)

            # v1.9.2: naming_result init (dir() anti-pattern fix)
            naming_result = None

            # v1.10.0 M1 T3.4: Phase 2 — feedback_loop + struct_recovery
            # Phase 1 artifact'larini seed olarak gecir (naming_result dahil
            # degil cunku feedback_loop uretir). feedback_loop step'inin
            # needs listesi Phase 1'den gelen her seyi kapsiyor.
            try:
                # v1.10.0 M4: computation_struct_recovery feedback_loop'tan
                # sonra, eski struct_recovery'den ONCE calisir -- MaxSMT
                # adaylarini StructRecoveryEngine'e candidate olarak gecmeli.
                runner_phase2 = PipelineRunner(steps=[
                    "feedback_loop",
                    "computation_struct_recovery",
                    "struct_recovery",
                ])
                step_ctx2 = runner_phase2.run(
                    context,
                    seed_artifacts=dict(step_ctx.artifacts),
                )
            except RuntimeError as exc:
                return StageResult(
                    stage_name=self.name,
                    success=False,
                    duration_seconds=time.monotonic() - start,
                    errors=errors + [str(exc)],
                    stats=stats,
                    artifacts=artifacts,
                )

            _b = step_ctx2.artifacts
            # feedback_loop produces
            naming_result = _b["naming_result"]
            _computation_result = _b["computation_result"]
            algo_result = _b["updated_algo_result"]
            eng_result = _b["updated_eng_result"]
            # feedback_loop icinde loop_decompiled_dir'i buna atar;
            # struct_recovery sonrasinda ise struct_recovery_decompiled_dir
            # guncellenmis dizini tasir.
            decompiled_dir = _b.get(
                "struct_recovery_decompiled_dir",
                _b["final_decompiled_dir"],
            )

            # stats/errors/pending artifact merge
            stats.update(step_ctx2.stats)
            errors.extend(step_ctx2.errors)
            _pending2 = (context.metadata or {}).get("artifacts_pending", {})
            if _pending2:
                artifacts.update(_pending2)
        else:
            # --- ESKI YOL (M1 boyunca korunuyor, reviewer onayinda silinecek) ---
            # Universal binary ise lipo-thin arm64 slice'i bul (macho.py olusturur)
            # Byte pattern matching icin fat binary degil, dogru arch slice kullanilmali.
            binary_for_byte_match = target.path
            if target.target_type == TargetType.UNIVERSAL_BINARY:
                raw_dir = context.workspace.get_stage_dir("raw")
                thin_arm64 = raw_dir / f"{target.name}_arm64"
                if thin_arm64.exists():
                    binary_for_byte_match = thin_arm64
                    stats["byte_match_binary"] = "arm64_slice"
                    logger.info(
                        "BytePatternMatcher: arm64 thin slice kullaniliyor: %s",
                        thin_arm64,
                    )
                else:
                    logger.warning(
                        "BytePatternMatcher: arm64 thin slice bulunamadi (%s), "
                        "fat binary kullanilacak -- arch mismatch olabilir",
                        thin_arm64,
                    )

            # Decompiled C dosyalarini bul
            decompiled_dir = deob_dir / "decompiled"
            if not decompiled_dir.exists():
                decompiled_dir = static_dir / "ghidra_output" / "decompiled"

            c_files = sorted(decompiled_dir.rglob("*.c")) if decompiled_dir.exists() else []
            if not c_files:
                return StageResult(
                    stage_name=self.name,
                    success=False,
                    duration_seconds=time.monotonic() - start,
                    errors=["Decompile edilmis C dosyasi bulunamadi"],
                )

            stats["source_c_files"] = len(c_files)
            logger.info("Binary reconstruction: %d C dosyasi islenecek", len(c_files))

            # v1.9.2: naming_result'i method basinda None olarak tanimla (dir() anti-pattern fix)
            naming_result = None

            # --- v1.4.3: File content cache (geri getirildi, lightweight) ---
            # v1.2.3'te RAM endisesiyle kaldirilmisti. Ancak downstream moduller
            # ayni dosyalari tekrar tekrar okuyor (ConfidenceCalibrator, InlineDetector vb.).
            # Tek seferlik okuma ile I/O tekrarini onluyoruz.
            _file_cache: dict[str, str] = {}
            for _cf in c_files:
                try:
                    _file_cache[_cf.name] = _cf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    logger.debug("Dosya cache'e okunamadi: %s, atlaniyor", _cf.name, exc_info=True)
            _cache_mb = sum(len(v) for v in _file_cache.values()) / (1024 * 1024)
            logger.info("File cache: %d dosya, %.1f MB", len(_file_cache), _cache_mb)
            # context uzerinden downstream modullere gecir
            if not hasattr(context, "metadata"):
                context.metadata = {}  # type: ignore[attr-defined]
            context.metadata["file_cache"] = _file_cache  # type: ignore[attr-defined]

            # Ghidra metadata dosyalarini bul -- deobf dizininde varsa oradan al (binary_deobfuscator kopyalar),
            # yoksa static'ten oku.
            functions_json = deob_dir / "ghidra_functions.json"
            if not functions_json.exists():
                functions_json = static_dir / "ghidra_functions.json"
            strings_json = deob_dir / "ghidra_strings.json"
            if not strings_json.exists():
                strings_json = static_dir / "ghidra_strings.json"
            call_graph_json = deob_dir / "ghidra_call_graph.json"
            if not call_graph_json.exists():
                call_graph_json = static_dir / "ghidra_call_graph.json"
            ghidra_types_json = deob_dir / "ghidra_types.json"
            if not ghidra_types_json.exists():
                ghidra_types_json = static_dir / "ghidra_types.json"
            xrefs_json = deob_dir / "ghidra_xrefs.json"
            if not xrefs_json.exists():
                xrefs_json = static_dir / "ghidra_xrefs.json"

            # P-Code ve CFG JSON'lari (v1.2.3+)
            pcode_json = deob_dir / "ghidra_pcode.json"
            if not pcode_json.exists():
                pcode_json = static_dir / "ghidra_pcode.json"
            cfg_json = deob_dir / "ghidra_cfg.json"
            if not cfg_json.exists():
                cfg_json = static_dir / "ghidra_cfg.json"

            # FunctionID JSON'i (v1.2.4+ PDB/FID sprint)
            fid_json = deob_dir / "ghidra_function_id.json"
            if not fid_json.exists():
                fid_json = static_dir / "ghidra_function_id.json"

            # v1.8: Ghidra decompiled.json (pcode_high_vars tip bilgisi icin)
            decompiled_json = deob_dir / "decompiled.json"
            if not decompiled_json.exists():
                decompiled_json = static_dir / "decompiled.json"
            if not decompiled_json.exists():
                # ghidra_output altinda da olabilir
                _ghidra_out = static_dir / "ghidra_output" / "decompiled.json"
                if _ghidra_out.exists():
                    decompiled_json = _ghidra_out

            output_dir = reconstructed_dir / "src"
            output_dir.mkdir(parents=True, exist_ok=True)

            # --- v1.2.2 Performans: JSON cache ---
            # functions_json ve strings_json tekrar tekrar parse ediliyor (8+ kez).
            # Bir kez parse et, cache'ten kullan.
            _func_data = None
            if functions_json and functions_json.exists():
                try:
                    _func_data = json.loads(
                        functions_json.read_text(encoding="utf-8", errors="replace"),
                    )
                except Exception as exc:
                    logger.warning("functions_json parse hatasi: %s -- %s", functions_json, exc)
                    errors.append(f"functions_json parse hatasi: {exc}")

            _string_data = None
            if strings_json and strings_json.exists():
                try:
                    _string_data = json.loads(
                        strings_json.read_text(encoding="utf-8", errors="replace"),
                    )
                except Exception as exc:
                    logger.warning("strings_json parse hatasi: %s -- %s", strings_json, exc)
                    errors.append(f"strings_json parse hatasi: {exc}")

            _call_graph_data = None
            if call_graph_json and call_graph_json.exists():
                try:
                    _call_graph_data = json.loads(
                        call_graph_json.read_text(encoding="utf-8", errors="replace"),
                    )
                except Exception as exc:
                    logger.warning("call_graph_json parse hatasi: %s -- %s", call_graph_json, exc)
                    errors.append(f"call_graph_json parse hatasi: {exc}")
                    pass

            # 0. Signature DB Matching (bilinen kutuphane fonksiyonlarini tani)
            context.report_progress("Signature DB matching...", 0.05)
            _step_start = time.monotonic()
            sig_matches = []

            # v1.8.0: Platform-aware signature filtering (Bug 7 fix)
            # v1.9.2: _TARGET_PLATFORM_MAP artik module-level constant
            _sig_platform = _TARGET_PLATFORM_MAP.get(target.target_type)

            try:
                from karadul.analyzers.signature_db import SignatureDB
                sig_db = SignatureDB(context.config, target_platform=_sig_platform)
                sig_matches = sig_db.match_all(
                    functions_json, strings_json, call_graph_json, decompiled_dir,
                    target_platform=_sig_platform,
                )
                stats["signature_matches"] = len(sig_matches)
                if sig_matches:
                    sig_path = context.workspace.save_json(
                        "reconstructed", "signature_matches", {
                            "total": len(sig_matches),
                            "matches": [
                                {"original": m.original_name, "matched": m.matched_name,
                                 "library": m.library, "confidence": m.confidence,
                                 "purpose": m.purpose}
                                for m in sig_matches
                            ],
                        },
                    )
                    artifacts["signature_matches"] = sig_path
                    logger.info(
                        "Signature DB: %d fonksiyon tanindi", len(sig_matches),
                    )
            except ImportError:
                logger.debug("SignatureDB modulu bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Signature DB hatasi: %s", exc)
                errors.append(f"Signature DB hatasi: {exc}")

            stats["timing_signature_db"] = round(time.monotonic() - _step_start, 1)

            context.report_progress("Byte pattern matching...", 0.10)
            # 0.5. Byte Pattern Matching -- FUN_xxx fonksiyonlarini byte pattern ile tani
            _step_start = time.monotonic()
            byte_pattern_names: dict[str, str] = {}
            if context.config.binary_reconstruction.enable_byte_pattern_matching:
                try:
                    from karadul.analyzers.byte_pattern_matcher import BytePatternMatcher

                    bpm = BytePatternMatcher(
                        min_confidence=context.config.binary_reconstruction.min_naming_confidence,
                    )

                    # FLIRT signature'larini topla (StaticAnalysisStage'de yuklenmis olabilir)
                    all_byte_sigs = []
                    try:
                        from karadul.analyzers.flirt_parser import FLIRTParser
                        fp = FLIRTParser()

                        # Homebrew + sigs/ + external path signature'lari
                        project_root = context.config.project_root

                        # Byte pattern'li signature'lar (build_byte_signatures.py ciktisi)
                        homebrew_bytes_sigs = project_root / "signatures_homebrew_bytes.json"
                        if homebrew_bytes_sigs.exists():
                            all_byte_sigs.extend(fp.load_json_signatures(homebrew_bytes_sigs))

                        # Genel homebrew sigs (isim-based, byte pattern olmayabilir)
                        homebrew_sigs = project_root / "signatures_homebrew.json"
                        if homebrew_sigs.exists():
                            all_byte_sigs.extend(fp.load_json_signatures(homebrew_sigs))

                        sigs_dir = project_root / "sigs"
                        if sigs_dir.is_dir():
                            all_byte_sigs.extend(fp.load_directory(sigs_dir))

                        ext_paths = context.config.binary_reconstruction.external_signature_paths
                        for ext_path in ext_paths:
                            p = Path(ext_path)
                            if p.is_file() and p.suffix == ".json":
                                all_byte_sigs.extend(fp.load_json_signatures(p))
                            elif p.is_file() and p.suffix == ".pat":
                                all_byte_sigs.extend(fp.load_pat_file(p))
                            elif p.is_dir():
                                all_byte_sigs.extend(fp.load_directory(p))

                        # Binary'den dogrudan symbol extraction (byte pattern'li)
                        # Universal binary ise thin slice kullan (arch uyumu icin)
                        binary_sigs = fp.extract_from_binary(binary_for_byte_match)
                        all_byte_sigs.extend(binary_sigs)
                    except Exception as exc:
                        logger.debug("FLIRT signature toplama hatasi: %s", exc)

                    if all_byte_sigs:
                        bp_result = bpm.match_unknown_functions(
                            binary_path=binary_for_byte_match,
                            functions_json=functions_json,
                            known_signatures=all_byte_sigs,
                        )
                        if bp_result.total_matched > 0:
                            byte_pattern_names = bpm.to_naming_map(bp_result)
                            stats["byte_pattern_matched"] = bp_result.total_matched
                            stats["byte_pattern_total_unknown"] = bp_result.total_unknown
                            stats["byte_pattern_match_rate"] = f"{bp_result.match_rate:.1%}"

                            # Sonuclari kaydet
                            bp_path = context.workspace.save_json(
                                "reconstructed", "byte_pattern_matches", {
                                    "total_matched": bp_result.total_matched,
                                    "total_unknown": bp_result.total_unknown,
                                    "match_rate": bp_result.match_rate,
                                    "duration_seconds": bp_result.duration_seconds,
                                    "matches": bp_result.matches,
                                },
                            )
                            artifacts["byte_pattern_matches"] = bp_path
                            logger.info(
                                "Byte Pattern Matching: %d/%d FUN_xxx tanindi (%.1f%%)",
                                bp_result.total_matched,
                                bp_result.total_unknown,
                                bp_result.match_rate * 100,
                            )
                        if bp_result.errors:
                            errors.extend(bp_result.errors)

                except ImportError:
                    logger.debug("BytePatternMatcher bulunamadi, atlaniyor")
                except Exception as exc:
                    logger.warning("Byte pattern matching hatasi: %s", exc)
                    errors.append(f"Byte pattern matching hatasi: {exc}")

            stats["timing_byte_pattern"] = round(time.monotonic() - _step_start, 1)

            # 0.7: P-Code dataflow analizi (opsiyonel, v1.2.3+)
            _step_start = time.monotonic()
            _pcode_result = None
            _pcode_naming_candidates = []  # v1.5: naming candidate'ler
            if pcode_json and pcode_json.exists():
                try:
                    with open(pcode_json, "r", encoding="utf-8") as _pf:
                        _pcode_header = _pf.read(4096)

                    _is_stats_only = '"mode": "stats_only"' in _pcode_header
                    _is_jsonl = '"mode": "jsonl"' in _pcode_header

                    if _is_stats_only:
                        # v1.4.4: stats_only — 4.7GB parse etme
                        _pcode_data = json.loads(_pcode_header)
                        stats["pcode_functions_analyzed"] = _pcode_data.get("total_functions", 0)
                        stats["pcode_total_ops"] = _pcode_data.get("total_pcode_ops", 0)
                        logger.info(
                            "P-Code stats-only: %d fonksiyon, %d op",
                            stats["pcode_functions_analyzed"],
                            stats["pcode_total_ops"],
                        )
                    elif _is_jsonl:
                        # v1.5: JSONL streaming — lightweight pcode analiz
                        from karadul.analyzers.pcode_analyzer import PcodeAnalyzer
                        _pcode_data = json.loads(_pcode_header)
                        _jsonl_path_str = _pcode_data.get("jsonl_path", "")

                        if _jsonl_path_str:
                            _jsonl_path = Path(_jsonl_path_str)
                        else:
                            # Fallback: pcode.json yanindaki pcode.jsonl
                            _jsonl_path = pcode_json.parent / "pcode.jsonl"

                        if _jsonl_path.exists():
                            pcode_analyzer = PcodeAnalyzer()
                            _pcode_result = pcode_analyzer.analyze_streaming(_jsonl_path)
                            stats["pcode_functions_analyzed"] = _pcode_result.total_functions
                            stats["pcode_total_ops"] = _pcode_result.total_pcode_ops

                            # v1.5: Naming candidate uretimi
                            for func_pcode in _pcode_result.functions:
                                nc_list = pcode_analyzer.generate_naming_candidates(func_pcode)
                                _pcode_naming_candidates.extend(nc_list)

                            stats["pcode_naming_candidates"] = len(_pcode_naming_candidates)
                            logger.info(
                                "P-Code JSONL: %d fonksiyon, %d op, %d naming candidate",
                                _pcode_result.total_functions,
                                _pcode_result.total_pcode_ops,
                                len(_pcode_naming_candidates),
                            )
                        else:
                            logger.warning("JSONL dosyasi bulunamadi: %s", _jsonl_path)
                            stats["pcode_functions_analyzed"] = _pcode_data.get("total_functions", 0)
                            stats["pcode_total_ops"] = _pcode_data.get("total_pcode_ops", 0)
                    else:
                        # Legacy: tam pcode JSON (eski davranis)
                        from karadul.analyzers.pcode_analyzer import PcodeAnalyzer
                        pcode_analyzer = PcodeAnalyzer()
                        _pcode_result = pcode_analyzer.analyze(pcode_json)
                        stats["pcode_functions_analyzed"] = _pcode_result.total_functions
                        stats["pcode_total_ops"] = _pcode_result.total_pcode_ops

                        # Legacy modda da naming candidate uret
                        for func_pcode in _pcode_result.functions:
                            nc_list = pcode_analyzer.generate_naming_candidates(func_pcode)
                            _pcode_naming_candidates.extend(nc_list)

                        logger.info(
                            "P-Code legacy: %d fonksiyon, %d op, %d naming candidate",
                            _pcode_result.total_functions,
                            _pcode_result.total_pcode_ops,
                            len(_pcode_naming_candidates),
                        )
                except ImportError:
                    logger.debug("PcodeAnalyzer bulunamadi, atlaniyor")
                except Exception as exc:
                    logger.warning("P-Code analiz hatasi: %s", exc)
            stats["timing_pcode"] = round(time.monotonic() - _step_start, 1)

            # 0.8: CFG analizi (opsiyonel, v1.2.3+)
            _step_start = time.monotonic()
            _cfg_result = None
            if cfg_json and cfg_json.exists():
                try:
                    from karadul.analyzers.cfg_analyzer import CFGAnalyzer
                    cfg_analyzer = CFGAnalyzer()
                    _cfg_result = cfg_analyzer.analyze(cfg_json)
                    stats["cfg_functions_analyzed"] = _cfg_result.total_functions
                    stats["cfg_total_blocks"] = _cfg_result.total_blocks
                    stats["cfg_total_edges"] = _cfg_result.total_edges
                    cfg_summary = cfg_analyzer.get_summary(_cfg_result)
                    stats["cfg_classification"] = cfg_summary.get("classification_distribution", {})
                    logger.info(
                        "CFG analiz: %d fonksiyon, %d blok, %d edge",
                        _cfg_result.total_functions,
                        _cfg_result.total_blocks,
                        _cfg_result.total_edges,
                    )
                except ImportError:
                    logger.debug("CFGAnalyzer bulunamadi, atlaniyor")
                except Exception as exc:
                    logger.warning("CFG analiz hatasi: %s", exc)
            stats["timing_cfg"] = round(time.monotonic() - _step_start, 1)

            context.report_progress("Algorithm ID + Binary Name Extraction...", 0.25)
            # 1 & 1.5: Algorithm ID ve Binary Name Extraction PARALEL
            _step_start = time.monotonic()
            # v1.9.2: Thread-safe -- her worker kendi result'ini return eder,
            # main thread'de merge edilir. nonlocal + shared dict anti-pattern kaldirildi.
            algo_result = None
            extracted_names: dict[str, str] = {}
            eng_result = None

            def _run_algorithm_id():
                """Algorithm Identification (constant + structural + API tarama)."""
                if not context.config.binary_reconstruction.enable_algorithm_id:
                    return {"success": False, "skipped": True}
                try:
                    from karadul.reconstruction.c_algorithm_id import CAlgorithmIdentifier
                    algo_id = CAlgorithmIdentifier(context.config)
                    _algo_res = algo_id.identify(decompiled_dir, functions_json, strings_json)
                    if _algo_res.success:
                        algo_path = context.workspace.save_json(
                            "reconstructed", "algorithms", {
                                "total": _algo_res.total_detected,
                                "algorithms": [
                                    {"name": a.name, "category": a.category,
                                     "confidence": a.confidence, "function": a.function_name,
                                     "evidence": a.evidence}
                                    for a in _algo_res.algorithms
                                ],
                            },
                        )
                        logger.info("Algorithm ID: %d tespit edildi", _algo_res.total_detected)
                        return {
                            "success": True,
                            "result": _algo_res,
                            "stats": {
                                "algorithms_detected": _algo_res.total_detected,
                                "algorithms_by_category": _algo_res.by_category,
                            },
                            "artifacts": {"algorithms": algo_path},
                        }
                    return {"success": True, "result": _algo_res, "stats": {}, "artifacts": {}}
                except Exception as exc:
                    logger.warning("Algorithm identification hatasi: %s", exc)
                    return {"success": False, "error": f"Algorithm ID hatasi: {exc}"}

            def _run_binary_name_extraction():
                """Binary Name Extraction (debug strings, build paths, RTTI)."""
                if not context.config.binary_reconstruction.enable_binary_name_extraction:
                    return {"success": False, "skipped": True}
                try:
                    from karadul.reconstruction.binary_name_extractor import BinaryNameExtractor
                    extractor = BinaryNameExtractor(context.config)
                    extract_result = extractor.extract(
                        strings_json=strings_json,
                        functions_json=functions_json,
                        call_graph_json=call_graph_json,
                    )
                    if extract_result.success and extract_result.names:
                        _names = {
                            n.original_name: n.recovered_name
                            for n in extract_result.names
                        }
                        extract_path = context.workspace.save_json(
                            "reconstructed", "binary_names", {
                                "total": len(_names),
                                "names": {n.original_name: {
                                    "recovered": n.recovered_name,
                                    "source": n.source,
                                    "confidence": n.confidence,
                                    "class": n.class_name,
                                } for n in extract_result.names},
                                "classes": extract_result.class_methods,
                            },
                        )
                        logger.info(
                            "Binary Name Extraction: %d isim, %d class",
                            len(_names), len(extract_result.class_methods),
                        )
                        return {
                            "success": True,
                            "result": _names,
                            "stats": {
                                "binary_names_extracted": len(_names),
                                "classes_detected": len(extract_result.class_methods),
                            },
                            "artifacts": {"binary_names": extract_path},
                        }
                    return {"success": True, "result": {}, "stats": {}, "artifacts": {}}
                except ImportError:
                    logger.debug("BinaryNameExtractor bulunamadi, atlaniyor")
                    return {"success": False, "skipped": True}
                except Exception as exc:
                    logger.warning("Binary name extraction hatasi: %s", exc)
                    return {"success": False, "error": f"Binary name extraction hatasi: {exc}"}

            def _run_engineering_analysis():
                """Engineering Algorithm Analysis (multi-domain: eng, finans, ML, DSP)."""
                if not context.config.binary_reconstruction.enable_engineering_analysis:
                    return {"success": False, "skipped": True}
                try:
                    from karadul.reconstruction.engineering import (
                        EngineeringAlgorithmAnalyzer,
                    )
                    eng_analyzer = EngineeringAlgorithmAnalyzer()
                    _eng_res = eng_analyzer.identify(decompiled_dir, functions_json)
                    if _eng_res and _eng_res.success:
                        eng_path = context.workspace.save_json(
                            "reconstructed", "engineering_algorithms", _eng_res.to_dict(),
                        )
                        logger.info(
                            "Engineering Algorithm ID: %d tespit edildi",
                            _eng_res.total_detected,
                        )
                        return {
                            "success": True,
                            "result": _eng_res,
                            "stats": {
                                "engineering_algorithms_detected": _eng_res.total_detected,
                                "engineering_by_category": _eng_res.by_category,
                            },
                            "artifacts": {"engineering_algorithms": eng_path},
                        }
                    return {"success": True, "result": _eng_res, "stats": {}, "artifacts": {}}
                except ImportError:
                    logger.debug("EngineeringAlgorithmAnalyzer bulunamadi, atlaniyor")
                    return {"success": False, "skipped": True}
                except Exception as exc:
                    logger.warning("Engineering algorithm analysis hatasi: %s", exc)
                    return {"success": False, "error": f"Engineering algorithm analysis hatasi: {exc}"}

            # Uc bagimsiz islemi paralel calistir
            logger.info("Algorithm ID + Engineering Analysis + Binary Name Extraction paralel baslatiliyor")
            with ThreadPoolExecutor(max_workers=3) as pool:
                algo_future = pool.submit(_run_algorithm_id)
                name_future = pool.submit(_run_binary_name_extraction)
                eng_future = pool.submit(_run_engineering_analysis)

            # v1.9.2: Main thread'de thread-safe merge
            _algo_dict = algo_future.result()
            _name_dict = name_future.result()
            _eng_dict = eng_future.result()

            if _algo_dict.get("success"):
                algo_result = _algo_dict.get("result")
                stats.update(_algo_dict.get("stats", {}))
                artifacts.update(_algo_dict.get("artifacts", {}))
            elif not _algo_dict.get("skipped") and "error" in _algo_dict:
                errors.append(_algo_dict["error"])

            if _name_dict.get("success"):
                extracted_names = _name_dict.get("result", {})
                stats.update(_name_dict.get("stats", {}))
                artifacts.update(_name_dict.get("artifacts", {}))
            elif not _name_dict.get("skipped") and "error" in _name_dict:
                errors.append(_name_dict["error"])

            if _eng_dict.get("success"):
                eng_result = _eng_dict.get("result")
                stats.update(_eng_dict.get("stats", {}))
                artifacts.update(_eng_dict.get("artifacts", {}))
            elif not _eng_dict.get("skipped") and "error" in _eng_dict:
                errors.append(_eng_dict["error"])

            stats["timing_algo_name_eng_parallel"] = round(time.monotonic() - _step_start, 1)

            # 1.5.1: Confidence Calibration -- engineering sonuclarini kalibre et
            _step_start = time.monotonic()
            calibrated_matches = None
            if eng_result and eng_result.success and eng_result.algorithms:
                try:
                    from karadul.reconstruction.engineering import ConfidenceCalibrator

                    calibrator = ConfidenceCalibrator()

                    # Call-graph ve function bodies cikar (varsa)
                    # v1.4.3: _file_cache'den oku (disk I/O tekrari yok)
                    func_bodies: dict[str, str] = {}
                    all_func_names: list[str] = []
                    try:
                        for _cf in c_files:
                            content = _file_cache.get(_cf.name)
                            if content is None:
                                try:
                                    content = _cf.read_text(encoding="utf-8", errors="replace")
                                except OSError:
                                    continue
                            for fm in re.finditer(
                                r"\b(\w+)\s*\([^)]*\)\s*\{", content,
                            ):
                                fn = fm.group(1)
                                if fn not in func_bodies:
                                    func_bodies[fn] = content[fm.start():fm.start() + 3000]
                                    all_func_names.append(fn)
                    except Exception:
                        logger.debug("Fonksiyon body parse basarisiz, atlaniyor", exc_info=True)

                    call_graph = calibrator.build_call_graph_from_bodies(
                        func_bodies, all_func_names,
                    )

                    calibrated_matches = calibrator.calibrate(
                        eng_result.algorithms,
                        call_graph,
                        all_func_names,
                        function_bodies=func_bodies or None,
                    )

                    if calibrated_matches:
                        cal_path = context.workspace.save_json(
                            "reconstructed", "engineering_calibrated",
                            {
                                "total": len(calibrated_matches),
                                "summary": calibrator.summarize(calibrated_matches),
                                "matches": [cm.to_dict() for cm in calibrated_matches],
                            },
                        )
                        artifacts["engineering_calibrated"] = cal_path
                        stats["engineering_calibrated_count"] = len(calibrated_matches)
                        logger.info(
                            "Confidence calibration: %d matches calibrated",
                            len(calibrated_matches),
                        )
                except ImportError:
                    logger.debug("ConfidenceCalibrator bulunamadi, atlaniyor")
                except Exception as exc:
                    logger.warning("Confidence calibration hatasi: %s", exc)
                    errors.append(f"Confidence calibration hatasi: {exc}")

            stats["timing_confidence_calibration"] = round(time.monotonic() - _step_start, 1)

            # 1.6: Engineering + Crypto sonuclarini birlestir
            if eng_result and eng_result.success and eng_result.algorithms:
                merged_algos = {
                    "total": (algo_result.total_detected if algo_result and algo_result.success else 0)
                        + eng_result.total_detected,
                    "crypto_algorithms": [a.to_dict() for a in (algo_result.algorithms if algo_result and algo_result.success else [])],
                    "engineering_algorithms": [a.to_dict() for a in eng_result.algorithms],
                }
                # Kalibre edilmis sonuclar varsa merged'e ekle
                if calibrated_matches:
                    merged_algos["calibrated"] = [cm.to_dict() for cm in calibrated_matches]
                merged_path = context.workspace.save_json(
                    "reconstructed", "algorithms_merged", merged_algos,
                )
                artifacts["algorithms_merged"] = merged_path

            # v1.4.3: Match Budget -- downstream modullerin isleyecegi match sayisini sinirla.
            # 18K+ match StructRecovery/SemanticNamer/CompositionAnalyzer'i yavaslatiyor.
            # En dusuk confidence match'leri kes, algo_result ve eng_result listelerini kirp.
            MAX_ALGO_MATCHES = context.config.binary_reconstruction.max_algo_matches
            _total_matches = (
                (len(algo_result.algorithms) if algo_result and algo_result.success else 0)
                + (len(eng_result.algorithms) if eng_result and eng_result.success else 0)
            )
            if MAX_ALGO_MATCHES > 0 and _total_matches > MAX_ALGO_MATCHES:
                logger.warning(
                    "Algorithm match budget: %d > %d, truncating by confidence",
                    _total_matches, MAX_ALGO_MATCHES,
                )
                # Tum match'leri birlesik listede sirala, en yuksek confidence'i tut
                _all_merged = []
                if algo_result and algo_result.success:
                    for a in algo_result.algorithms:
                        _all_merged.append(("crypto", a))
                if eng_result and eng_result.success:
                    for a in eng_result.algorithms:
                        _all_merged.append(("eng", a))
                _all_merged.sort(
                    key=lambda x: x[1].confidence if hasattr(x[1], "confidence") else (
                        x[1].get("confidence", 0) if isinstance(x[1], dict) else 0
                    ),
                    reverse=True,
                )
                _all_merged = _all_merged[:MAX_ALGO_MATCHES]
                # Ayristir ve geri yaz
                _kept_crypto = [a for tag, a in _all_merged if tag == "crypto"]
                _kept_eng = [a for tag, a in _all_merged if tag == "eng"]
                if algo_result and algo_result.success:
                    algo_result.algorithms = _kept_crypto
                if eng_result and eng_result.success:
                    eng_result.algorithms = _kept_eng
                logger.info(
                    "Match budget applied: crypto=%d, eng=%d (total=%d)",
                    len(_kept_crypto), len(_kept_eng), len(_kept_crypto) + len(_kept_eng),
                )
                stats["match_budget_original"] = _total_matches
                stats["match_budget_kept"] = len(_kept_crypto) + len(_kept_eng)

            # 1.8. Byte pattern sonuclarini extracted_names'e merge et
            # (byte_pattern_names c_namer'in pre_names'ine gidecek)
            if byte_pattern_names:
                # Byte pattern eslestirmeleri yuksek guvenilirlik --
                # binary_name_extractor sonuclari varsa onlari EZMEsin diye
                # sadece henuz isimlendirilmemis fonksiyonlari ekle.
                for old_name, new_name in byte_pattern_names.items():
                    if old_name not in extracted_names:
                        extracted_names[old_name] = new_name
                logger.info(
                    "Byte pattern names merged: %d isim (toplam extracted_names: %d)",
                    len(byte_pattern_names), len(extracted_names),
                )

            # 1.8.5: CAPA capability sonuclarini naming'e entegre et
            _capa_capabilities: dict = {}  # addr -> [cap_name, ...]  (comment pipeline icin de)
            _step_start = time.monotonic()
            if context.config.binary_reconstruction.enable_capa:
                try:
                    _capa_data = context.workspace.load_json("static", "capa_capabilities")
                    if _capa_data and _capa_data.get("success"):
                        func_caps = _capa_data.get("function_capabilities", {})
                        _capa_capabilities = func_caps  # Ham veriyi koru (comment icin)

                        # Capability'den fonksiyon isimleri uret
                        from karadul.analyzers.capa_scanner import (
                            capability_to_function_name,
                            rank_capabilities,
                            CAPACapability,
                        )
                        _capa_names_added = 0
                        for func_addr, cap_list in func_caps.items():
                            if func_addr in extracted_names:
                                continue  # Daha guvenilir bir kaynak zaten isim vermis
                            if not cap_list:
                                continue
                            # Cap dicts'i CAPACapability'ye cevir ve sirala
                            caps = [
                                CAPACapability(
                                    name=c.get("name", ""),
                                    namespace=c.get("namespace", ""),
                                )
                                for c in cap_list
                                if isinstance(c, dict)
                            ]
                            ranked = rank_capabilities(caps)
                            if ranked:
                                best_name = capability_to_function_name(ranked[0].name)
                                if best_name:
                                    extracted_names[func_addr] = best_name
                                    _capa_names_added += 1

                        if _capa_names_added > 0:
                            logger.info(
                                "CAPA names merged: %d isim (toplam extracted_names: %d)",
                                _capa_names_added, len(extracted_names),
                            )
                            stats["capa_names_added"] = _capa_names_added
                except FileNotFoundError:
                    logger.debug("CAPA sonuclari bulunamadi (static stage'de calistirilmamis)")
                except Exception as exc:
                    logger.debug("CAPA naming entegrasyonu hatasi: %s", exc)
            stats["timing_capa_naming"] = round(time.monotonic() - _step_start, 1)

        # 1.9. Assembly Analysis -- Ghidra decompiler fallback
        # v1.10.0 M1 T3.5: Step registry modunda bu is asm_analysis step'i
        # tarafindan Phase 1'de zaten yapildi. Eski yolda bu blok calisir.
        _step_start = time.monotonic()
        # Ghidra JSON'daki fonksiyonlarda disassembly field'i varsa,
        # assembly-level analiz ile ek bilgi cikarir (calling convention,
        # param count, SIMD/crypto pattern, stack frame).
        if _use_step_registry:
            # Phase 1 assembly_analysis step'i calistirdi — stats/artifacts
            # zaten merge edildi. Burada tekrar etmeye gerek yok.
            pass
        else:
            try:
                from karadul.analyzers.assembly_analyzer import AssemblyAnalyzer

                asm_analyzer = AssemblyAnalyzer()
                if functions_json.exists():
                    # Mimariyi hedef tipinden cikar
                    arch = "x86_64"
                    # v1.2.2: _func_data cache'den kullan, tekrar parse etme
                    # v1.9.2: Explicit None + type check -- _func_data list/str olabilir
                    _asm_func_data = _func_data if isinstance(_func_data, dict) else None
                    if _asm_func_data is None:
                        try:
                            _asm_func_data = json.loads(
                                functions_json.read_text(encoding="utf-8", errors="replace"),
                            )
                        except Exception:
                            logger.debug("Assembly functions JSON parse basarisiz", exc_info=True)
                            _asm_func_data = {}
                    if target.target_type == TargetType.MACHO_BINARY:
                        meta = _asm_func_data.get("metadata", {}) if isinstance(_asm_func_data, dict) else {}
                        proc = meta.get("processor", "").lower()
                        if "aarch64" in proc or "arm" in proc:
                            arch = "aarch64"

                    asm_results = asm_analyzer.analyze_from_ghidra_json(functions_json, arch=arch)

                    if asm_results:
                        # Assembly analiz sonuclarini stats'a ekle
                        crypto_funcs = [
                            name for name, r in asm_results.items()
                            if r.has_crypto_instructions
                        ]
                        simd_funcs = [
                            name for name, r in asm_results.items()
                            if r.simd_patterns
                        ]
                        stats["asm_functions_analyzed"] = len(asm_results)
                        if crypto_funcs:
                            stats["asm_crypto_functions"] = crypto_funcs[:20]
                        if simd_funcs:
                            stats["asm_simd_functions"] = simd_funcs[:20]

                        # Assembly analizi workspace'e kaydet
                        try:
                            asm_data = {
                                "total_analyzed": len(asm_results),
                                "crypto_functions": crypto_funcs,
                                "simd_functions": simd_funcs,
                                "details": {
                                    name: {
                                        "calling_convention": r.calling_convention,
                                        "param_count": r.param_count,
                                        "stack_frame_size": r.stack_frame_size,
                                        "is_leaf": r.is_leaf_function,
                                        "complexity": r.estimated_complexity,
                                        "has_crypto": r.has_crypto_instructions,
                                        "simd_count": len(r.simd_patterns),
                                    }
                                    for name, r in list(asm_results.items())[:500]
                                },
                            }
                            asm_path = context.workspace.save_json(
                                "reconstructed", "assembly_analysis", asm_data,
                            )
                            artifacts["assembly_analysis"] = asm_path
                        except Exception:
                            logger.debug("Assembly analysis artifact kaydi basarisiz", exc_info=True)

                        logger.info(
                            "Assembly Analysis: %d fonksiyon (%d crypto, %d SIMD)",
                            len(asm_results), len(crypto_funcs), len(simd_funcs),
                        )
            except ImportError:
                logger.debug("AssemblyAnalyzer bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Assembly analysis hatasi (atlaniyor): %s", exc)

            stats["timing_assembly_analysis"] = round(time.monotonic() - _step_start, 1)

        # ================================================================
        # v1.7.5: Incremental pipeline feedback loop
        # Type recovery, computation recovery ve name merger iteratif calisir.
        # Her turda: computation -> c_naming -> name_merger -> type_recovery
        # Convergence: yeni isimlendirilen fonksiyon sayisi < %1 ise dur.
        # Ghidra decompile, algorithm ID, engineering analysis TEKRAR ETMEZ.
        #
        # v1.7.5 DEGISIKLIK: Buyuk binary cap KALDIRILDI. Bunun yerine
        # iterasyon 2+ sadece degisen dosyalari + 1-hop komsularini isler.
        # 19K fonksiyonlu binary'de iter2-3 artik ~1K dosya isler (vs 19K).
        # ================================================================
        _configured_iterations = max(1, context.config.binary_reconstruction.pipeline_iterations)
        _convergence_threshold = context.config.binary_reconstruction.pipeline_convergence_threshold

        # v1.7.5: Buyuk binary cap KALDIRILDI — tum boyutlarda config degeri kullanilir.
        # Hiz, iterasyon sayisini kismaktan degil, incremental processing'den gelir.
        _func_count = len(c_files)
        _max_iterations = _configured_iterations

        _iteration_timeout = 600.0  # 10 dakika per-iteration timeout (guvenlik agi)
        _prev_named_set: set[str] = set()  # onceki iterasyonda isimlendirilen semboller
        _iteration_stats: list[dict] = []  # her iterasyonun istatistikleri
        _loop_decompiled_dir = decompiled_dir  # loop boyunca degisen kaynak dizin
        _loop_start = time.monotonic()

        # v1.7.5: Call graph adjacency index — 1-hop komsu hesaplamasi icin.
        # Sadece bir kez insa edilir, iterasyonlar arasi degismez.
        _cg_neighbors: dict[str, set[str]] = {}  # func_name -> {caller/callee names}
        if _call_graph_data:
            _cg_build_start = time.monotonic()
            for _fn, _node in _call_graph_data.items():
                if not isinstance(_node, dict):
                    continue
                neighbors = _cg_neighbors.setdefault(_fn, set())
                for c in _node.get("callees", []):
                    _callee_name = c.get("name", c) if isinstance(c, dict) else str(c)
                    if _callee_name:
                        neighbors.add(_callee_name)
                        _cg_neighbors.setdefault(_callee_name, set()).add(_fn)
                for c in _node.get("callers", []):
                    _caller_name = c.get("name", c) if isinstance(c, dict) else str(c)
                    if _caller_name:
                        neighbors.add(_caller_name)
                        _cg_neighbors.setdefault(_caller_name, set()).add(_fn)
            logger.info(
                "Call graph adjacency index: %d nodes, built in %.2fs",
                len(_cg_neighbors), time.monotonic() - _cg_build_start,
            )

        # v1.7.5: c_files filename -> Path mapping (incremental filtre icin)
        _cfile_by_name: dict[str, Path] = {cf.name: cf for cf in c_files}

        # v1.7.5: Degisen dosya seti — iter 0'da None (tum dosyalar islenir),
        # iter 1+ icin onceki turda isimlendirilen + 1-hop komsulari.
        _incremental_files: list[Path] | None = None  # None = tum dosyalar

        if _max_iterations > 1:
            logger.info(
                "Pipeline feedback loop: max %d iterasyon (incremental mode), "
                "convergence esik %.2f%%, per-iteration timeout %.0fs, %d functions",
                _max_iterations, _convergence_threshold * 100, _iteration_timeout,
                _func_count,
            )

        # v1.9.2 QW2: rglob cache -- loop icinde tekrarlanan rglob("*.c") cagrisi
        # yerine cache kullan. decompiled_dir degistiginde invalidate edilir.
        _rglob_c_files: list[Path] = sorted(decompiled_dir.rglob("*.c")) if decompiled_dir.exists() else []
        _rglob_cfile_map: dict[str, Path] = {cf.name: cf for cf in _rglob_c_files}
        _rglob_cached_dir: Path = decompiled_dir

        def _refresh_rglob_cache() -> None:
            nonlocal _rglob_c_files, _rglob_cfile_map, _rglob_cached_dir
            if decompiled_dir != _rglob_cached_dir:
                _rglob_c_files = sorted(decompiled_dir.rglob("*.c")) if decompiled_dir.exists() else []
                _rglob_cfile_map = {cf.name: cf for cf in _rglob_c_files}
                _rglob_cached_dir = decompiled_dir

        # v1.9.2 QW4: Module pre-instantiation -- loop disinda bir kez olustur
        _pre_comp_engine = None
        _pre_c_namer = None
        _pre_type_rec = None
        if context.config.computation_recovery.enabled:
            try:
                from karadul.reconstruction.recovery_layers import ComputationRecoveryEngine
                _pre_comp_engine = ComputationRecoveryEngine(context.config)
            except ImportError:
                pass
        if context.config.binary_reconstruction.enable_c_naming:
            try:
                from karadul.reconstruction.c_namer import CVariableNamer
                _pre_c_namer = CVariableNamer(context.config)
            except ImportError:
                pass
        if context.config.binary_reconstruction.enable_type_recovery:
            try:
                from karadul.reconstruction.c_type_recoverer import CTypeRecoverer
                _pre_type_rec = CTypeRecoverer(context.config)
            except ImportError:
                pass

        for _pipeline_iter in range(_max_iterations):
            _iter_start = time.monotonic()
            _iter_new_names = 0  # bu turda eklenen yeni isimler
            _current_named_set: set[str] = set()  # bu turda isimlendirilenler

            # v1.7.5: Incremental mode bilgisi
            _processing_count = len(_incremental_files) if _incremental_files is not None else _func_count
            logger.info(
                "=== Pipeline iteration %d/%d starting: %d/%d functions%s ===",
                _pipeline_iter + 1, _max_iterations,
                _processing_count, _func_count,
                " (incremental)" if _incremental_files is not None else " (full)",
            )
            # Iterasyon > 0 ise decompiled_dir'i loop'un son ciktisina geri al
            if _pipeline_iter > 0:
                decompiled_dir = _loop_decompiled_dir
                _refresh_rglob_cache()  # v1.9.2 QW2: decompiled_dir degisti

            # v1.7.4: iterasyon etiketi (progress mesajlari icin)
            _iter_label = f" (iter {_pipeline_iter + 1})" if _pipeline_iter > 0 else ""

            # v1.4.0: Computation Recovery (opsiyonel)
            logger.info("  Computation recovery (iter %d)...", _pipeline_iter + 1)  # v1.7.4
            _step_start = time.monotonic()
            _computation_result = None
            if context.config.computation_recovery.enabled:
                context.report_progress(f"Computation Recovery{_iter_label}...", 0.35)
                try:
                    comp_engine = _pre_comp_engine  # v1.9.2 QW4: pre-instantiated
                    if comp_engine is None:
                        raise ImportError("ComputationRecoveryEngine pre-init basarisiz")

                    # Mevcut sonuclari engine'e besle
                    _existing_sig = {
                        "matches": [
                            {"original": m.original_name, "matched": m.matched_name,
                             "library": m.library, "confidence": m.confidence}
                            for m in sig_matches
                        ],
                    } if sig_matches else None
                    _existing_algo = algo_result.to_dict() if (
                        algo_result and hasattr(algo_result, "to_dict") and algo_result.success
                    ) else None
                    _existing_eng = eng_result.to_dict() if (
                        eng_result and hasattr(eng_result, "to_dict") and eng_result.success
                    ) else None

                    # v1.5.9: Go binary tespiti
                    _is_go = getattr(context.target, "target_type", None) == TargetType.GO_BINARY

                    # v1.7.5: Incremental computation — iter 2+ sadece degisen dosyalar
                    _comp_input_dir = decompiled_dir
                    _incr_comp_dir: Path | None = None
                    if _incremental_files is not None and _pipeline_iter > 0:
                        _incr_comp_dir = Path(
                            tempfile.mkdtemp(
                                prefix=f"incr_comp_iter{_pipeline_iter}_",
                                dir=reconstructed_dir,
                            )
                        )
                        _incr_comp_names = {f.name for f in _incremental_files}
                        _refresh_rglob_cache()
                        for _cf in _rglob_c_files:
                            if _cf.name in _incr_comp_names:
                                _cdst = _incr_comp_dir / _cf.name
                                try:
                                    _cdst.symlink_to(_cf.resolve())
                                except (OSError, NotImplementedError):
                                    shutil.copy2(_cf, _cdst)
                        _comp_input_dir = _incr_comp_dir
                        logger.info(
                            "Incremental computation: %d/%d files",
                            len(_incr_comp_names), _func_count,
                        )

                    # v1.8.0: binary_hash icin target'in SHA256'sinin ilk 16 karakteri
                    _binary_hash_16 = getattr(context.target, "file_hash", "")[:16]

                    _computation_result = comp_engine.recover(
                        decompiled_dir=_comp_input_dir,
                        functions_json=functions_json if functions_json.exists() else None,
                        call_graph_json=call_graph_json if call_graph_json.exists() else None,
                        cfg_json=cfg_json if cfg_json.exists() else None,
                        ghidra_types_json=ghidra_types_json if ghidra_types_json.exists() else None,
                        existing_sig_matches=_existing_sig,
                        existing_algo_matches=_existing_algo,
                        existing_eng_matches=_existing_eng,
                        is_go_binary=_is_go,
                        binary_hash=_binary_hash_16,
                    )
                    if _computation_result and _computation_result.success:
                        stats["computation_structs_refined"] = _computation_result.structs_refined
                        stats["computation_arrays_detected"] = _computation_result.arrays_detected
                        stats["computation_types_propagated"] = _computation_result.types_propagated
                        stats["computation_cfg_matches"] = _computation_result.cfg_matches
                        stats["computation_fusion_ids"] = _computation_result.fusion_identifications
                        stats["computation_formulas"] = _computation_result.formulas_extracted
                        stats["computation_param_types"] = len(
                            _computation_result.param_type_inferences or {},
                        )
                        stats["computation_return_types"] = len(
                            _computation_result.return_type_inferences or {},
                        )
                        stats["computation_globals"] = len(
                            _computation_result.global_variables or [],
                        )
                        stats["computation_naming_candidates"] = len(
                            _computation_result.naming_candidates or [],
                        )

                        # v1.5.1: computation naming candidate'leri extracted_names'e
                        # YAZMIYORUZ — confidence laundering bug'ı. Candidate'ler
                        # satir 1828'de dogrudan candidates_by_symbol'e gidiyor
                        # (orijinal confidence ve source korunarak).
                        # Ayrica sadece FUN_/sub_/thunk_ fonksiyonlara isim ver,
                        # debug sembolu olan fonksiyonlari EZME.
                        pass

                        # Sonuclari artifact olarak kaydet
                        try:
                            comp_path = context.workspace.save_json(
                                "reconstructed", "computation_recovery",
                                _computation_result.to_dict(),
                            )
                            artifacts["computation_recovery"] = comp_path
                        except Exception:
                            logger.debug("Computation recovery artifact kaydi basarisiz", exc_info=True)

                        logger.info(
                            "Computation Recovery: %d struct, %d array, %d cfg match, "
                            "%d fusion id, %d formula",
                            _computation_result.structs_refined,
                            _computation_result.arrays_detected,
                            _computation_result.cfg_matches,
                            _computation_result.fusion_identifications,
                            _computation_result.formulas_extracted,
                        )
                    # Gecici incremental dizini temizle
                    if _incr_comp_dir and _incr_comp_dir.exists():
                        shutil.rmtree(_incr_comp_dir, ignore_errors=True)
                except ImportError:
                    logger.debug("ComputationRecoveryEngine bulunamadi, atlaniyor")
                except Exception as exc:
                    logger.warning("Computation recovery hatasi (atlaniyor): %s", exc)
                    # Temizle (exception durumunda da)
                    try:
                        if _incr_comp_dir and _incr_comp_dir.exists():
                            shutil.rmtree(_incr_comp_dir, ignore_errors=True)
                    except NameError:
                        pass
            stats[f"timing_computation_recovery_iter{_pipeline_iter}"] = round(time.monotonic() - _step_start, 1)
            logger.info("  Computation recovery (iter %d) done: %.1fs", _pipeline_iter + 1, stats[f"timing_computation_recovery_iter{_pipeline_iter}"])

            context.report_progress(f"C Variable/Function Naming{_iter_label}...", 0.45)
            # 2. C Variable/Function Naming
            logger.info("  C naming (iter %d)...", _pipeline_iter + 1)
            _step_start = time.monotonic()
            naming_result = None  # Name merger icin dis scope'ta tanimla
            if context.config.binary_reconstruction.enable_c_naming:
                try:
                    namer = _pre_c_namer  # v1.9.2 QW4: pre-instantiated
                    if namer is None:
                        raise ImportError("CVariableNamer pre-init basarisiz")

                    # v1.7.5: Incremental mode — iter 2+ sadece degisen dosyalari isle.
                    # c_namer decompiled_dir icindeki *.c dosyalarini tarar.
                    # Incremental modda, gecici bir dizin olusturup sadece
                    # degisen dosyalara symlink koyuyoruz.
                    _namer_dir = decompiled_dir
                    _incr_namer_dir: Path | None = None
                    if _incremental_files is not None and _pipeline_iter > 0:
                        _incr_namer_dir = Path(
                            tempfile.mkdtemp(
                                prefix=f"incr_naming_iter{_pipeline_iter}_",
                                dir=reconstructed_dir,
                            )
                        )
                        _incr_names_set = {f.name for f in _incremental_files}
                        _refresh_rglob_cache()
                        for _cf in _rglob_c_files:
                            if _cf.name in _incr_names_set:
                                _dst = _incr_namer_dir / _cf.name
                                try:
                                    _dst.symlink_to(_cf.resolve())
                                except (OSError, NotImplementedError):
                                    shutil.copy2(_cf, _dst)
                        _namer_dir = _incr_namer_dir
                        logger.info(
                            "Incremental c_namer: %d/%d files",
                            len(_incr_names_set), _func_count,
                        )

                    # v1.7.5: iter > 0 icin output_dir ayir (cakisma onleme)
                    _namer_output = output_dir
                    if _pipeline_iter > 0:
                        _namer_output = reconstructed_dir / f"src_iter{_pipeline_iter}"
                        _namer_output.mkdir(parents=True, exist_ok=True)

                    naming_result = namer.analyze_and_rename(
                        _namer_dir, functions_json, strings_json,
                        call_graph_json, _namer_output,
                        pre_names=extracted_names or None,
                        xrefs_json=xrefs_json if xrefs_json.exists() else None,
                    )
                    if naming_result.success:
                        stats["variables_renamed"] = naming_result.total_renamed
                        stats["naming_by_strategy"] = naming_result.by_strategy
                        stats["naming_high_confidence"] = naming_result.high_confidence
                        artifacts["named_sources"] = _namer_output
                        # v1.7.5: Incremental modda decompiled_dir degistirme —
                        # c_namer subset ciktisi sadece naming_map icin kullanilir.
                        # Name merger Aho-Corasick replacement'i decompiled_dir'deki
                        # TUM dosyalari (veya incremental seti) isler.
                        # Full modda ise c_namer'in ciktisini kullan.
                        if not (_incremental_files is not None and _pipeline_iter > 0):
                            decompiled_dir = _namer_output
                            _refresh_rglob_cache()  # v1.9.2 QW2: decompiled_dir degisti
                        logger.info(
                            "C Naming: %d isim degistirildi%s",
                            naming_result.total_renamed,
                            " (incremental)" if (_incremental_files is not None and _pipeline_iter > 0) else "",
                        )
                    else:
                        errors.extend(naming_result.errors)

                    # Gecici incremental dizini temizle
                    if _incr_namer_dir and _incr_namer_dir.exists():
                        shutil.rmtree(_incr_namer_dir, ignore_errors=True)
                except Exception as exc:
                    logger.warning("C naming hatasi: %s", exc)
                    errors.append(f"C naming hatasi: {exc}")

            stats[f"timing_c_naming_iter{_pipeline_iter}"] = round(time.monotonic() - _step_start, 1)

            # 2.4 BinDiff -- fonksiyon eslestirmesi (3 kaynak: config, ref_db cache, refdiff)
            # v1.7.4: BinDiff sonucu iterasyonlar arasi degismez, sadece ilk turda calistir
            # v1.7.6: reference_binary config zorunlulugu kaldirildi -- ref_db otomatik taranir
            bindiff_names: dict[str, str] = {}
            # Per-match confidence bilgisi: target_name -> (ref_name, confidence, method)
            _bindiff_confidence_map: dict[str, tuple[str, float, str]] = {}

            if _pipeline_iter == 0:
                try:
                    from karadul.analyzers.bindiff import BinaryDiffer
                    differ = BinaryDiffer()

                    # Target verilerini hazirla (cache'den veya dosyadan)
                    _target_func_data = _func_data if isinstance(_func_data, dict) else (
                        json.loads(functions_json.read_text(encoding="utf-8", errors="replace"))
                        if functions_json.exists() else None
                    )
                    _target_str_data = _string_data if _string_data is not None else (
                        json.loads(strings_json.read_text(encoding="utf-8", errors="replace"))
                        if strings_json.exists() else None
                    )

                    # --- Kaynak (a): reference_binary config (geriye uyumlu) ---
                    ref_binary = getattr(context.config.binary_reconstruction, 'reference_binary', '')
                    if ref_binary and Path(ref_binary).exists():
                        try:
                            ref_functions_json = Path(ref_binary).parent / "ghidra_functions.json"
                            ref_strings_json = Path(ref_binary).parent / "ghidra_strings.json"

                            if ref_functions_json.exists() and _target_func_data:
                                ref_data = json.loads(
                                    ref_functions_json.read_text(encoding="utf-8", errors="replace")
                                )
                                ref_str_data = None
                                if ref_strings_json.exists():
                                    ref_str_data = json.loads(
                                        ref_strings_json.read_text(encoding="utf-8", errors="replace")
                                    )

                                diff_result = differ.compare(
                                    reference=ref_data,
                                    target=_target_func_data,
                                    ref_strings=ref_str_data,
                                    target_strings=_target_str_data,
                                )
                                _conf_map = differ.transfer_names_with_confidence(diff_result)
                                if _conf_map:
                                    _bindiff_confidence_map.update(_conf_map)
                                    bindiff_names.update(differ.transfer_names(diff_result))
                                    stats["bindiff_config_matches"] = len(_conf_map)
                                    stats["bindiff_config_match_rate"] = diff_result.match_rate
                                    logger.info(
                                        "BinDiff(config): %d fonksiyon eslesti (match_rate=%.2f)",
                                        len(_conf_map), diff_result.match_rate,
                                    )
                            else:
                                logger.debug(
                                    "BinDiff(config): referans Ghidra ciktilari bulunamadi (%s)",
                                    ref_functions_json if ref_binary else "N/A",
                                )
                        except Exception as exc:
                            logger.warning("BinDiff(config) hatasi (atlaniyor): %s", exc)

                    # --- Kaynak (b): ref_db cache otomatik tarama ---
                    # reference_binary config olmasa bile ref_db'deki tum reference
                    # binary'leri otomatik olarak BinDiff'e besle.
                    if _target_func_data:
                        try:
                            ref_db_path = getattr(
                                context.config.binary_reconstruction, 'reference_db_path', ''
                            )
                            _ref_db_dir = Path(ref_db_path) if ref_db_path else (
                                Path.home() / ".cache" / "karadul" / "ref_db"
                            )

                            if _ref_db_dir.exists():
                                from karadul.reconstruction.reference_differ import ReferenceDB
                                _ref_db = ReferenceDB(_ref_db_dir)
                                _ref_db_entries = _ref_db.all_entries()

                                # call_graph loop disinda bir kez oku (Codex audit: tekrarlanan I/O fix)
                                _target_cg_data = None
                                if call_graph_json.exists():
                                    try:
                                        _target_cg_data = json.loads(
                                            call_graph_json.read_text(
                                                encoding="utf-8", errors="replace"
                                            )
                                        )
                                    except Exception:
                                        logger.debug("Call graph JSON parse basarisiz (refdb)", exc_info=True)

                                _refdb_total = 0
                                for _rdb_entry in _ref_db_entries:
                                    if not _rdb_entry.functions_json.exists():
                                        continue
                                    try:
                                        _rdb_funcs = json.loads(
                                            _rdb_entry.functions_json.read_text(
                                                encoding="utf-8", errors="replace"
                                            )
                                        )
                                        _rdb_strings = None
                                        if _rdb_entry.strings_json and _rdb_entry.strings_json.exists():
                                            _rdb_strings = json.loads(
                                                _rdb_entry.strings_json.read_text(
                                                    encoding="utf-8", errors="replace"
                                                )
                                            )
                                        _rdb_call_graph = None
                                        if _rdb_entry.call_graph_json and _rdb_entry.call_graph_json.exists():
                                            _rdb_call_graph = json.loads(
                                                _rdb_entry.call_graph_json.read_text(
                                                    encoding="utf-8", errors="replace"
                                                )
                                            )

                                        # call_graph loop disinda bir kez okundu (_target_cg_data)
                                        _rdb_diff = differ.compare(
                                            reference=_rdb_funcs,
                                            target=_target_func_data,
                                            ref_strings=_rdb_strings,
                                            target_strings=_target_str_data,
                                            ref_call_graph=_rdb_call_graph,
                                            target_call_graph=_target_cg_data,
                                        )
                                        _rdb_conf = differ.transfer_names_with_confidence(_rdb_diff)
                                        if _rdb_conf:
                                            # Daha onceki eslesmelerle cakisma kontrolu:
                                            # sadece daha yuksek confidence varsa guncelle
                                            for t_name, (ref_name, conf, method) in _rdb_conf.items():
                                                existing = _bindiff_confidence_map.get(t_name)
                                                if existing is None or conf > existing[1]:
                                                    _bindiff_confidence_map[t_name] = (ref_name, conf, method)
                                                    bindiff_names[t_name] = ref_name
                                            _refdb_total += len(_rdb_conf)
                                            logger.debug(
                                                "BinDiff(ref_db): %s/%s -- %d eslesti",
                                                _rdb_entry.library, _rdb_entry.version,
                                                len(_rdb_conf),
                                            )
                                    except Exception as _rdb_exc:
                                        logger.debug(
                                            "BinDiff(ref_db): %s/%s hatasi: %s",
                                            _rdb_entry.library, _rdb_entry.version, _rdb_exc,
                                        )
                                        continue

                                if _refdb_total > 0:
                                    stats["bindiff_refdb_matches"] = _refdb_total
                                    logger.info(
                                        "BinDiff(ref_db): toplam %d fonksiyon eslesti (%d kutuphane)",
                                        _refdb_total, len(_ref_db_entries),
                                    )
                        except ImportError:
                            logger.debug("BinDiff(ref_db): ReferenceDB import edilemedi")
                        except Exception as exc:
                            logger.warning("BinDiff(ref_db) hatasi (atlaniyor): %s", exc)

                    # BinDiff toplam istatistik
                    if bindiff_names:
                        stats["bindiff_matches"] = len(bindiff_names)
                        extracted_names.update(bindiff_names)
                        logger.info(
                            "BinDiff toplam: %d fonksiyon eslesti",
                            len(bindiff_names),
                        )
                except ImportError:
                    logger.debug("BinDiff modulu bulunamadi, atlaniyor")
                except Exception as exc:
                    logger.warning("BinDiff hatasi (atlaniyor): %s", exc)
                    errors.append(f"BinDiff hatasi: {exc}")

            # 2.4b Reference Differ -- string'lerden versiyon tespiti + CFG matching
            # v1.7.4: ReferenceDiffer sonucu degismez, sadece ilk turda calistir
            _refdiff_naming: dict[str, str] = {}
            if getattr(context.config.binary_reconstruction, 'enable_reference_differ', True) and _pipeline_iter == 0:
                try:
                    from karadul.reconstruction.reference_differ import (
                        ReferenceDiffer, VersionDetector,
                    )

                    # String verisinden versiyon tespiti
                    _string_data_for_refdiff = _string_data if _string_data is not None else (
                        json.loads(strings_json.read_text(encoding="utf-8", errors="replace"))
                        if strings_json.exists() else None
                    )
                    if _string_data_for_refdiff:
                        vdetector = VersionDetector()
                        detections = vdetector.detect_from_strings(_string_data_for_refdiff)

                        if detections:
                            stats["refdiff_detections"] = [
                                {"lib": d.library, "ver": d.version, "conf": d.confidence}
                                for d in detections
                            ]

                            # v1.7.4: Reference DB eslestirme (auto-populate destekli)
                            ref_db_path = getattr(
                                context.config.binary_reconstruction, 'reference_db_path', ''
                            )
                            _ref_path = Path(ref_db_path) if ref_db_path else Path.home() / ".cache" / "karadul" / "ref_db"
                            _ref_path.mkdir(parents=True, exist_ok=True)
                            if detections:  # Version tespit edildiyse eslestir
                                differ = ReferenceDiffer(
                                    reference_db_path=_ref_path,
                                    auto_populate=True,
                                )
                                _func_data_for_refdiff = _func_data if _func_data is not None else (
                                    json.loads(functions_json.read_text(encoding="utf-8", errors="replace"))
                                    if functions_json.exists() else None
                                )
                                _cfg_data_for_refdiff = None
                                if cfg_json.exists():
                                    try:
                                        _cfg_data_for_refdiff = json.loads(
                                            cfg_json.read_text(encoding="utf-8", errors="replace")
                                        )
                                    except Exception:
                                        logger.debug("CFG JSON parse basarisiz (refdiff)", exc_info=True)
                                _cg_data_for_refdiff = None
                                if call_graph_json.exists():
                                    try:
                                        _cg_data_for_refdiff = json.loads(
                                            call_graph_json.read_text(encoding="utf-8", errors="replace")
                                        )
                                    except Exception:
                                        logger.debug("Call graph JSON parse basarisiz (refdiff)", exc_info=True)

                                for det in detections:
                                    rd_result = differ.match(
                                        target_functions=_func_data_for_refdiff or {},
                                        target_strings=_string_data_for_refdiff,
                                        target_cfg=_cfg_data_for_refdiff,
                                        target_call_graph=_cg_data_for_refdiff,
                                        detection=det,
                                    )
                                    if rd_result and rd_result.naming_map:
                                        _refdiff_naming.update(rd_result.naming_map)
                                        stats[f"refdiff_{det.library}_matches"] = rd_result.matched
                                        stats[f"refdiff_{det.library}_rate"] = rd_result.match_rate

                                if _refdiff_naming:
                                    extracted_names.update(_refdiff_naming)
                                    logger.info(
                                        "ReferenceDiffer: %d fonksiyon eslesti",
                                        len(_refdiff_naming),
                                    )
                            else:
                                logger.debug(
                                    "ReferenceDiffer: reference_db_path bos veya mevcut degil, "
                                    "sadece versiyon tespiti yapildi"
                                )
                except ImportError:
                    logger.debug("ReferenceDiffer modulu bulunamadi, atlaniyor")
                except Exception as exc:
                    logger.warning("ReferenceDiffer hatasi (atlaniyor): %s", exc)
                    errors.append(f"ReferenceDiffer hatasi: {exc}")

            stats[f"timing_reference_differ_iter{_pipeline_iter}"] = round(time.monotonic() - _step_start, 1)
            logger.info("  Naming merge (iter %d)...", _pipeline_iter + 1)  # v1.7.4
            _step_start = time.monotonic()

            # 2.5 Name Merger -- binary_extractor + c_namer sonuclarini birlestir
            if NameMerger is not None:
                try:
                    merger = NameMerger(
                        min_confidence=context.config.binary_reconstruction.min_naming_confidence,
                        merger_config=context.config.name_merger,
                    )
                    candidates_by_symbol: dict[str, list] = {}

                    # binary_name_extractor sonuclarini candidate olarak ekle
                    for old_name, new_name in extracted_names.items():
                        # Bos, cok kisa veya gecersiz isimleri atla --
                        # bos string regex'te \b()\b olarak her kelime sinirina
                        # eslenir ve tum dosyayi bozar.
                        if not old_name or len(old_name) < 2 or not new_name:
                            continue
                        candidates_by_symbol.setdefault(old_name, []).append(
                            NamingCandidate(new_name, 0.85, "binary_extractor")
                        )

                    # c_namer sonuclarini candidate olarak ekle
                    if naming_result is not None and hasattr(naming_result, "naming_map"):
                        for old_name, new_name in naming_result.naming_map.items():
                            if not old_name or len(old_name) < 2 or not new_name:
                                continue
                            candidates_by_symbol.setdefault(old_name, []).append(
                                NamingCandidate(new_name, 0.70, "c_namer")
                            )

                    # v1.7.6: BinDiff sonuclarini per-match confidence ile ekle
                    # (binary_extractor'un sabit 0.85'i yerine gercek match confidence)
                    if _bindiff_confidence_map:
                        for old_name, (new_name, conf, method) in _bindiff_confidence_map.items():
                            if not old_name or len(old_name) < 2 or not new_name:
                                continue
                            candidates_by_symbol.setdefault(old_name, []).append(
                                NamingCandidate(new_name, conf, f"bindiff_{method}")
                            )
                        logger.debug(
                            "BinDiff: %d candidate (per-match confidence) Name Merger'a eklendi",
                            len(_bindiff_confidence_map),
                        )

                    # ReferenceDiffer sonuclarini candidate olarak ekle (yuksek guven)
                    if _refdiff_naming:
                        for old_name, new_name in _refdiff_naming.items():
                            if not old_name or len(old_name) < 2 or not new_name:
                                continue
                            candidates_by_symbol.setdefault(old_name, []).append(
                                NamingCandidate(new_name, 0.95, "reference_differ")
                            )
                        logger.debug(
                            "ReferenceDiffer: %d candidate Name Merger'a eklendi",
                            len(_refdiff_naming),
                        )

                    # FunctionID sonuclarini candidate olarak ekle (opsiyonel)
                    if fid_json and fid_json.exists():
                        try:
                            _fid_data = json.loads(
                                fid_json.read_text(encoding="utf-8", errors="replace"),
                            )
                            for m in _fid_data.get("matches", []):
                                fid_name = m.get("name", "")
                                fid_addr = m.get("address", "")
                                if not fid_name or not fid_addr:
                                    continue
                                # FunctionID isimleri FUN_xxx -> gercek isim eslemesi
                                # Adres bazli eslestirme: func_data'dan FUN_ ismini bul
                                fun_key = "FUN_%s" % fid_addr.lstrip("0x").lstrip("0")
                                if len(fun_key) >= 2:
                                    candidates_by_symbol.setdefault(fun_key, []).append(
                                        NamingCandidate(fid_name, 0.95, "function_id")
                                    )
                            logger.debug(
                                "FunctionID: %d candidate eklendi",
                                _fid_data.get("total_matches", 0),
                            )
                        except Exception as exc:
                            logger.debug("FunctionID candidate yuklenemedi: %s", exc)

                    # v1.4.0: Computation Recovery candidate'leri ekle
                    if _computation_result and _computation_result.success:
                        _comp_candidates_added = 0
                        for nc in _computation_result.naming_candidates:
                            func_name = nc.get("function_name", "")
                            cand_name = nc.get("candidate_name", "")
                            cand_conf = nc.get("confidence", 0.0)
                            cand_src = nc.get("source", "computation_recovery")
                            if not func_name or len(func_name) < 2 or not cand_name:
                                continue
                            # v1.5.1: Debug sembol korumasi — zaten anlamli ismi
                            # olan fonksiyonlara computation candidate ekleme
                            _is_unnamed = (
                                func_name.startswith("FUN_")
                                or func_name.startswith("sub_")
                                or func_name.startswith("thunk_")
                                or func_name.startswith("_unnamed_")
                            )
                            if not _is_unnamed:
                                continue
                            # v1.5.3 -> v1.6.6: signature_fusion threshold dusuruldu.
                            # DS fusion zaten min_belief (0.5) ile filtreliyor.
                            # Eski 0.80 esigi TUM candidate'leri olduruyordu
                            # (612/612 reddedildi cunku fused_confidence 0.50-0.61 arasi).
                            # Simdi Name Merger'in Bayesian merge + min_naming_confidence
                            # (0.7) yeterli kalite kontrolu sagliyor.
                            # Sadece cok dusuk guvenli olanlar (< 0.40) eleniyor.
                            if cand_src == "signature_fusion" and cand_conf < 0.40:
                                continue
                            # v1.7: callee_profile iteratif propagasyon --
                            # daha dusuk confidence'a sahip olabilir, 0.30 esigi.
                            if cand_src == "callee_profile" and cand_conf < 0.30:
                                continue
                            candidates_by_symbol.setdefault(func_name, []).append(
                                NamingCandidate(cand_name, cand_conf, cand_src)
                            )
                            _comp_candidates_added += 1
                        if _comp_candidates_added:
                            logger.debug(
                                "Computation Recovery: %d naming candidate eklendi",
                                _comp_candidates_added,
                            )

                        # v1.8.0: Cross-binary transfer candidate'leri
                        _cross_matches = _computation_result.layer_results.get(
                            "cross_binary_matches", [],
                        )
                        if _cross_matches and _pipeline_iter == 0:
                            _cross_added = 0
                            for _cm in _cross_matches:
                                _cm_func = _cm.get("func_name", "")
                                _cm_name = _cm.get("matched_name", "")
                                _cm_conf = _cm.get("confidence", 0.0)
                                if not _cm_func or not _cm_name:
                                    continue
                                # Sadece unnamed fonksiyonlara isim ver
                                _is_unnamed = (
                                    _cm_func.startswith("FUN_")
                                    or _cm_func.startswith("sub_")
                                    or _cm_func.startswith("thunk_")
                                )
                                if not _is_unnamed:
                                    continue
                                candidates_by_symbol.setdefault(_cm_func, []).append(
                                    NamingCandidate(
                                        _cm_name, _cm_conf,
                                        "cross_binary_transfer",
                                        reason="CFG fingerprint match from cached binary %s" % (
                                            _cm.get("source_binary", "?"),
                                        ),
                                    )
                                )
                                _cross_added += 1
                            if _cross_added:
                                logger.info(
                                    "Cross-binary transfer: %d naming candidate eklendi",
                                    _cross_added,
                                )
                                stats["cross_binary_candidates"] = _cross_added

                    # v1.5: P-Code dataflow naming candidate'leri
                    if _pcode_naming_candidates:
                        _pcode_added = 0
                        for nc in _pcode_naming_candidates:
                            func_name = nc.get("function_name", "")
                            cand_name = nc.get("candidate_name", "")
                            cand_conf = nc.get("confidence", 0.0)
                            cand_src = nc.get("source", "pcode_dataflow")

                            # Boost entry'leri (candidate_name bos) naming icin degil, skip
                            if not cand_name or not func_name:
                                continue
                            # v1.5.1: Debug sembol korumasi
                            _is_unnamed = (
                                func_name.startswith("FUN_")
                                or func_name.startswith("sub_")
                                or func_name.startswith("thunk_")
                                or func_name.startswith("_unnamed_")
                            )
                            if not _is_unnamed:
                                continue

                            candidates_by_symbol.setdefault(func_name, []).append(
                                NamingCandidate(cand_name, cand_conf, cand_src,
                                               reason=nc.get("reason", ""))
                            )
                            _pcode_added += 1

                        if _pcode_added > 0:
                            logger.info("P-Code naming: %d candidate eklendi", _pcode_added)

                    if candidates_by_symbol:
                        merge_result = merger.merge(candidates_by_symbol)
                        final_naming_map = merger.to_naming_map(merge_result)
                        logger.info(
                            "Name merger: %d merged (%d exact_multi, %d conflicts)",
                            merge_result.total_merged,
                            merge_result.exact_multi_matches,
                            merge_result.conflicts_resolved,
                        )
                        stats["name_merger_total"] = merge_result.total_merged
                        stats["name_merger_exact_multi"] = merge_result.exact_multi_matches
                        stats["name_merger_conflicts"] = merge_result.conflicts_resolved

                        # Merged naming_map'i dosyalara uygula
                        # Bos/kisa key'leri cikar -- regex \b()\b bos string her
                        # kelime sinirina eslenir, dosyayi bozar
                        final_naming_map = {
                            k: v for k, v in final_naming_map.items()
                            if k and len(k) >= 2 and v
                        }
                        if final_naming_map:
                            from karadul.reconstruction.aho_replacer import AhoReplacer
                            _aho_merger = AhoReplacer(final_naming_map)
                            _merge_suffix = f"_iter{_pipeline_iter}" if _pipeline_iter > 0 else ""
                            merge_dir = reconstructed_dir / f"merged{_merge_suffix}"
                            merge_dir.mkdir(parents=True, exist_ok=True)

                            # v1.2.2 -> v1.3: Aho-Corasick ile 140x hizlanma
                            # 19K dosyada regex ~570s -> AC ~4s

                            def _merge_one_file(c_file: Path) -> int:
                                content = c_file.read_text(
                                    encoding="utf-8", errors="replace",
                                )
                                new_content = _aho_merger.replace(content)
                                (merge_dir / c_file.name).write_text(
                                    new_content, encoding="utf-8",
                                )
                                return 1 if new_content != content else 0

                            # v1.7.5: Incremental merge — iter 2+ sadece degisen
                            # dosyalari + 1-hop komsularini isle, gerisini kopyala.
                            _refresh_rglob_cache()
                            _all_merge_files = list(_rglob_c_files)
                            if _incremental_files is not None and _pipeline_iter > 0:
                                _incr_names = {f.name for f in _incremental_files}
                                _merge_process = [f for f in _all_merge_files if f.name in _incr_names]
                                _merge_copy = [f for f in _all_merge_files if f.name not in _incr_names]
                                # Degismeyenleri aynen kopyala (hardlink = hizli, fallback copy)
                                for _cf in _merge_copy:
                                    _dst = merge_dir / _cf.name
                                    if not _dst.exists():
                                        try:
                                            os.link(_cf, _dst)  # hardlink = 0 I/O
                                        except (OSError, NotImplementedError):
                                            shutil.copy2(_cf, _dst)
                                logger.info(
                                    "Incremental merge: %d files to process, %d copied unchanged",
                                    len(_merge_process), len(_merge_copy),
                                )
                            else:
                                _merge_process = _all_merge_files

                            _renamed_count = 0
                            with ThreadPoolExecutor(max_workers=CPU_PERF_CORES) as _pool:
                                for result in _pool.map(_merge_one_file, _merge_process):
                                    _renamed_count += result

                            decompiled_dir = merge_dir
                            _refresh_rglob_cache()  # v1.9.2 QW2: decompiled_dir degisti
                            artifacts["merged_names"] = merge_dir
                            # Bu iterasyonda isimlendirilen sembolleri kaydet
                            _current_named_set = set(final_naming_map.keys())
                            logger.info(
                                "Name merger: %d isim dosyalara uygulandi (%d dosya degisti, "
                                "%d processed, %d total, %d worker)",
                                len(final_naming_map), _renamed_count,
                                len(_merge_process), len(_all_merge_files), CPU_PERF_CORES,
                            )
                except Exception as exc:
                    logger.warning("Name merger hatasi (atlaniyor): %s", exc)
                    errors.append(f"Name merger hatasi: {exc}")

            stats[f"timing_name_merger_iter{_pipeline_iter}"] = round(time.monotonic() - _step_start, 1)
            logger.info("  Name merger (iter %d) done: %.1fs", _pipeline_iter + 1, stats[f"timing_name_merger_iter{_pipeline_iter}"])  # v1.7.4

            context.report_progress(f"Type Recovery{_iter_label}...", 0.60)
            # 3. Type Recovery
            logger.info("  Type recovery (iter %d)...", _pipeline_iter + 1)
            _step_start = time.monotonic()
            if context.config.binary_reconstruction.enable_type_recovery:
                try:
                    type_rec = _pre_type_rec  # v1.9.2 QW4: pre-instantiated
                    if type_rec is None:
                        raise ImportError("CTypeRecoverer pre-init basarisiz")
                    _type_suffix = f"_iter{_pipeline_iter}" if _pipeline_iter > 0 else ""
                    type_dir = reconstructed_dir / f"typed{_type_suffix}"
                    type_dir.mkdir(parents=True, exist_ok=True)
                    # v1.4.1: Computation recovery struct'larini type_recoverer'a gec
                    _comp_structs_for_type = None
                    if _computation_result and _computation_result.success:
                        _cs_layer = _computation_result.layer_results.get(
                            "constraint_solver",
                        )
                        if _cs_layer and hasattr(_cs_layer, "structs") and _cs_layer.structs:
                            _comp_structs_for_type = [
                                s.to_dict() if hasattr(s, "to_dict") else s
                                for s in _cs_layer.structs
                            ]
                            logger.debug(
                                "Computation -> TypeRecovery: %d struct aktarilacak",
                                len(_comp_structs_for_type),
                            )

                    # v1.7.5: Incremental type recovery — iter 2+ sadece degisen dosyalar.
                    # Type recoverer decompiled_dir icindeki *.c dosyalarini tarar.
                    _type_input_dir = decompiled_dir
                    _incr_type_dir: Path | None = None
                    if _incremental_files is not None and _pipeline_iter > 0:
                        _incr_type_dir = Path(
                            tempfile.mkdtemp(
                                prefix=f"incr_type_iter{_pipeline_iter}_",
                                dir=reconstructed_dir,
                            )
                        )
                        _incr_type_names = {f.name for f in _incremental_files}
                        _refresh_rglob_cache()
                        for _cf in _rglob_c_files:
                            if _cf.name in _incr_type_names:
                                _dst = _incr_type_dir / _cf.name
                                try:
                                    _dst.symlink_to(_cf.resolve())
                                except (OSError, NotImplementedError):
                                    shutil.copy2(_cf, _dst)
                        _type_input_dir = _incr_type_dir
                        logger.info(
                            "Incremental type recovery: %d/%d files",
                            len(_incr_type_names), _func_count,
                        )

                    type_result = type_rec.recover(
                        _type_input_dir, functions_json, type_dir,
                        strings_json=strings_json,
                        ghidra_types_json=ghidra_types_json,
                        computation_structs=_comp_structs_for_type,
                        call_graph_json=call_graph_json,
                        decompiled_json=decompiled_json if decompiled_json.exists() else None,
                    )
                    if type_result.success:
                        stats["structs_recovered"] = len(type_result.structs)
                        stats["enums_recovered"] = len(type_result.enums)
                        stats["total_types_recovered"] = type_result.total_types_recovered
                        if type_result.types_header:
                            artifacts["types_header"] = type_result.types_header
                        # Sonraki adimlar typed output'u kullansin
                        if type_result.output_files:
                            decompiled_dir = type_dir
                            _refresh_rglob_cache()  # v1.9.2 QW2: decompiled_dir degisti
                        logger.info(
                            "Type Recovery: %d struct, %d enum",
                            len(type_result.structs), len(type_result.enums),
                        )
                    else:
                        errors.extend(type_result.errors)
                    # v1.7.5: Incremental type recovery icin: type_dir'e
                    # islenmemis dosyalari onceki decompiled_dir'den kopyala.
                    # Boylece type_dir tam bir cikti dizini olur.
                    if _incr_type_dir and type_result.success and type_result.output_files:
                        _refresh_rglob_cache()
                        for _cf in _rglob_c_files:
                            _tdst = type_dir / _cf.name
                            if not _tdst.exists():
                                try:
                                    os.link(_cf, _tdst)
                                except (OSError, NotImplementedError):
                                    shutil.copy2(_cf, _tdst)

                    # Gecici incremental dizini temizle
                    if _incr_type_dir and _incr_type_dir.exists():
                        shutil.rmtree(_incr_type_dir, ignore_errors=True)
                except Exception as exc:
                    logger.warning("Type recovery hatasi: %s", exc)
                    errors.append(f"Type recovery hatasi: {exc}")

            stats[f"timing_type_recovery_iter{_pipeline_iter}"] = round(time.monotonic() - _step_start, 1)
            logger.info("  Type recovery (iter %d) done: %.1fs", _pipeline_iter + 1, stats[f"timing_type_recovery_iter{_pipeline_iter}"])

            # v1.8.6: XTRIDE N-gram tip cikarimi -- type recovery'den sonra ek katman
            _xtride_step_start = time.monotonic()
            if context.config.binary_reconstruction.enable_xtride_typing:
                try:
                    from karadul.reconstruction.xtride_typer import XTrideTyper
                    _xtride = XTrideTyper()
                    _xtride_total = 0
                    _xtride_improved = 0

                    # Decompiled C dosyalarini tara
                    _refresh_rglob_cache()
                    _xtride_files = list(_rglob_c_files)
                    if _incremental_files is not None and _pipeline_iter > 0:
                        _xtride_incr_names = {f.name for f in _incremental_files}
                        _xtride_files = [f for f in _xtride_files if f.name in _xtride_incr_names]

                    # v1.9.2 QW3: re.compile cache -- her _xvar icin pattern bir kez derlenir
                    _xtride_pat_cache: dict[str, re.Pattern] = {}
                    for _xf in _xtride_files:
                        try:
                            _xcode = _xf.read_text(encoding="utf-8", errors="replace")
                            _xresult = _xtride.infer_types(_xcode, _xf.stem)
                            _xtride_total += _xresult.total_inferred
                            # Degisken bildirimlerini iyilestir: undefined8 -> gercek tip
                            if _xresult.inferences:
                                _xnew_code = _xcode
                                _xchanged = False
                                for _xvar, _xinf in _xresult.inferences.items():
                                    if _xinf.confidence < 0.50:
                                        continue
                                    # Ghidra bildirimindeki tipi bul ve degistir
                                    # Pattern: "  undefined8 param_1;" -> "  char * param_1;"
                                    if _xvar not in _xtride_pat_cache:
                                        _xtride_pat_cache[_xvar] = re.compile(
                                            r"^(\s*)(?:undefined[1248]?|long|ulong)\s+"
                                            + re.escape(_xvar)
                                            + r"(\s*[;=])",
                                            re.MULTILINE,
                                        )
                                    _xdecl_pat = _xtride_pat_cache[_xvar]
                                    _xm = _xdecl_pat.search(_xnew_code)
                                    if _xm:
                                        _xold = _xm.group(0)
                                        _xnew = f"{_xm.group(1)}{_xinf.inferred_type} {_xvar}{_xm.group(2)}"
                                        _xnew_code = _xnew_code.replace(_xold, _xnew, 1)
                                        _xchanged = True
                                        _xtride_improved += 1
                                if _xchanged:
                                    _xf.write_text(_xnew_code, encoding="utf-8")
                        except Exception:
                            logger.debug("Xtride type inference dosya islemi basarisiz, atlaniyor", exc_info=True)

                    stats["xtride_total_inferences"] = _xtride_total
                    stats["xtride_type_improvements"] = _xtride_improved
                    stats["xtride_pattern_count"] = _xtride.pattern_count
                    logger.info(
                        "  XTRIDE typing (iter %d): %d inferences, %d type improvements "
                        "(%d files, %d patterns)",
                        _pipeline_iter + 1, _xtride_total, _xtride_improved,
                        len(_xtride_files), _xtride.pattern_count,
                    )
                except Exception as exc:
                    logger.warning("XTRIDE typing hatasi (atlaniyor): %s", exc)
                    errors.append(f"XTRIDE typing hatasi: {exc}")
            stats[f"timing_xtride_typing_iter{_pipeline_iter}"] = round(time.monotonic() - _xtride_step_start, 1)

            # v1.9.1: Dynamic naming ONCE calisir (runtime evidence > statistical guess)
            # Sira: XTRIDE (tip) -> Dynamic (runtime isim) -> N-gram (istatistik isim)
            _dyn_step_start = time.monotonic()
            if context.config.binary_reconstruction.enable_dynamic_naming:
                try:
                    from karadul.reconstruction.dynamic_namer import DynamicNamer
                    _trace_path = context.workspace.get_stage_dir("dynamic") / "trace_report.json"
                    if _trace_path.exists():
                        _dyn_namer = DynamicNamer(trace_report_path=_trace_path)
                        if _dyn_namer.load_trace():
                            _dyn_total = 0
                            _dyn_applied = 0
                            _dyn_threshold = context.config.binary_reconstruction.ngram_confidence_threshold

                            _refresh_rglob_cache()
                            _dyn_files = list(_rglob_c_files)
                            if _incremental_files is not None and _pipeline_iter > 0:
                                _dyn_incr_names = {f.name for f in _incremental_files}
                                _dyn_files = [f for f in _dyn_files if f.name in _dyn_incr_names]

                            # v1.9.2 QW3: re.compile cache
                            _dyn_pat_cache: dict[str, re.Pattern] = {}
                            for _df in _dyn_files:
                                try:
                                    _dcode = _df.read_text(encoding="utf-8", errors="replace")
                                    _dsuggestions = _dyn_namer.infer_names(_df.stem, _dcode)
                                    _dyn_total += len(_dsuggestions)

                                    if _dsuggestions:
                                        _dchanged = False
                                        for _ds in _dsuggestions:
                                            if _ds.confidence < _dyn_threshold:
                                                continue
                                            if _ds.var_name not in _dyn_pat_cache:
                                                _dyn_pat_cache[_ds.var_name] = re.compile(
                                                    r"\b" + re.escape(_ds.var_name) + r"\b"
                                                )
                                            _dpat = _dyn_pat_cache[_ds.var_name]
                                            _dnew, _dcnt = _dpat.subn(_ds.suggested_name, _dcode)
                                            if _dcnt > 0:
                                                _dcode = _dnew
                                                _dchanged = True
                                                _dyn_applied += 1
                                        if _dchanged:
                                            _df.write_text(_dcode, encoding="utf-8")
                                except Exception:
                                    logger.debug("Dynamic rename dosya islemi basarisiz, atlaniyor", exc_info=True)

                            stats["dynamic_total_suggestions"] = _dyn_total
                            stats["dynamic_names_applied"] = _dyn_applied
                            logger.info(
                                "  Dynamic naming (iter %d): %d suggestions, %d applied",
                                _pipeline_iter + 1, _dyn_total, _dyn_applied,
                            )
                except Exception as exc:
                    logger.warning("Dynamic naming hatasi (atlaniyor): %s", exc)
                    errors.append(f"Dynamic naming hatasi: {exc}")
            stats[f"timing_dynamic_naming_iter{_pipeline_iter}"] = round(time.monotonic() - _dyn_step_start, 1)

            # v1.8.7: N-gram name prediction -- Dynamic naming'den sonra isim tahmini
            _ngram_step_start = time.monotonic()
            if context.config.binary_reconstruction.enable_ngram_naming:
                try:
                    from karadul.reconstruction.ngram_namer import NgramNamer
                    _ngram_db_dir = context.config.project_root / "sigs" / "ngram_name_db"
                    if _ngram_db_dir.is_dir():
                        _ngram_namer = NgramNamer(db_dir=_ngram_db_dir)
                        _ngram_total = 0
                        _ngram_applied = 0
                        _ngram_threshold = context.config.binary_reconstruction.ngram_confidence_threshold

                        _refresh_rglob_cache()
                        _ngram_files = list(_rglob_c_files)
                        if _incremental_files is not None and _pipeline_iter > 0:
                            _ngram_incr_names = {f.name for f in _incremental_files}
                            _ngram_files = [f for f in _ngram_files if f.name in _ngram_incr_names]

                        # v1.9.2 QW3: re.compile cache
                        _ngram_pat_cache: dict[str, re.Pattern] = {}
                        for _nf in _ngram_files:
                            try:
                                _ncode = _nf.read_text(encoding="utf-8", errors="replace")
                                _nresult = _ngram_namer.predict(_ncode, _nf.stem)
                                _ngram_total += _nresult.total_predicted

                                if _nresult.predictions:
                                    _nchanged = False
                                    for _nvar, _npred in _nresult.predictions.items():
                                        if _npred.confidence < _ngram_threshold:
                                            continue
                                        # Basit word-boundary replace
                                        if _nvar not in _ngram_pat_cache:
                                            _ngram_pat_cache[_nvar] = re.compile(
                                                r"\b" + re.escape(_nvar) + r"\b"
                                            )
                                        _npat = _ngram_pat_cache[_nvar]
                                        _nnew_code, _nsubs = _npat.subn(
                                            _npred.predicted_name, _ncode
                                        )
                                        if _nsubs > 0:
                                            _ncode = _nnew_code
                                            _nchanged = True
                                            _ngram_applied += 1
                                    if _nchanged:
                                        _nf.write_text(_ncode, encoding="utf-8")
                            except Exception:
                                logger.debug("N-gram prediction dosya islemi basarisiz, atlaniyor", exc_info=True)

                        stats["ngram_total_predictions"] = _ngram_total
                        stats["ngram_names_applied"] = _ngram_applied
                        logger.info(
                            "  N-gram naming (iter %d): %d predictions, %d applied (%d files)",
                            _pipeline_iter + 1, _ngram_total, _ngram_applied,
                            len(_ngram_files),
                        )
                except Exception as exc:
                    logger.warning("N-gram naming hatasi (atlaniyor): %s", exc)
                    errors.append(f"N-gram naming hatasi: {exc}")
            stats[f"timing_ngram_naming_iter{_pipeline_iter}"] = round(time.monotonic() - _ngram_step_start, 1)

            # Loop decompiled_dir'i guncelle (sonraki iterasyon icin)
            _loop_decompiled_dir = decompiled_dir

            # v1.7.4: Convergence check -- bu turda kac YENI isim eklendi
            _newly_named = _current_named_set - _prev_named_set
            _iter_new_names = len(_newly_named)
            _current_total = len(_current_named_set)

            _iter_duration = time.monotonic() - _iter_start  # v1.7.4
            _iter_stats = {
                "iteration": _pipeline_iter + 1,
                "new_names": _iter_new_names,
                "total_names": _current_total,
                "duration": round(_iter_duration, 2),
            }
            _iteration_stats.append(_iter_stats)
            logger.info(
                "Pipeline iteration %d/%d complete: %d new names (total %d), %.1fs",  # v1.7.4
                _pipeline_iter + 1, _max_iterations,
                _iter_new_names, _current_total,
                _iter_duration,
            )

            # v1.7.4: Per-iteration timeout -- iterasyon 10dk'yi astiysa kalan iterasyonlari atla
            if _iter_duration > _iteration_timeout and _pipeline_iter < _max_iterations - 1:
                logger.warning(
                    "Pipeline iteration %d took %.0fs (> %.0fs timeout), "
                    "skipping remaining %d iteration(s)",
                    _pipeline_iter + 1, _iter_duration, _iteration_timeout,
                    _max_iterations - _pipeline_iter - 1,
                )
                break

            # Ilk iterasyondan sonra convergence kontrol et
            if _pipeline_iter > 0:
                if len(_prev_named_set) > 0:
                    _new_ratio = _iter_new_names / len(_prev_named_set)
                else:
                    _new_ratio = 0.0 if _iter_new_names == 0 else 1.0

                if _new_ratio < _convergence_threshold:
                    logger.info(
                        "Pipeline converged: yeni isim orani %.3f < esik %.3f, "
                        "iterasyon %d'de duruyoruz",
                        _new_ratio, _convergence_threshold, _pipeline_iter + 1,
                    )
                    break

            _prev_named_set = _current_named_set.copy()

            # Son iterasyonda veya convergence'ta loop biter
            if _pipeline_iter < _max_iterations - 1:
                # v1.7.5: Incremental file set hesapla — sonraki iterasyonda
                # sadece bu dosyalar + 1-hop komsulari islenir.
                # _newly_named = bu turda ilk kez isimlendirilen semboller.
                # Her sembol bir .c dosyasina karsilik gelir (FUN_xxx.c).
                # 1-hop: bu fonksiyonlarin call graph'taki caller/callee'leri.
                if _newly_named and _cg_neighbors:
                    _affected_funcs: set[str] = set()
                    for _sym in _newly_named:
                        _affected_funcs.add(_sym)
                        # 1-hop komsulari
                        for _neighbor in _cg_neighbors.get(_sym, set()):
                            _affected_funcs.add(_neighbor)

                    # Fonksiyon adi -> dosya adi eslestirme.
                    # Ghidra decompile dosya adlari genelde "FUN_xxx.c" veya
                    # "fonksiyon_adi.c" seklinde. _cfile_by_name'den eslestir.
                    _next_incr: list[Path] = []
                    # Guncel decompiled_dir'deki dosyalari guncelle
                    _refresh_rglob_cache()
                    _current_cfiles = dict(_rglob_cfile_map)
                    for _fname, _fpath in _current_cfiles.items():
                        # Dosya adi ".c" uzantisiz halinin _affected_funcs'ta olup olmadigini kontrol et
                        _stem = _fpath.stem  # "FUN_001234" from "FUN_001234.c"
                        if _stem in _affected_funcs:
                            _next_incr.append(_fpath)

                    # Eger incremental set cok kucukse (< %2) veya cok buyukse (> %80),
                    # fallback: full processing. Cok kucuk = tum komsu bilgisi eksik;
                    # cok buyuk = incremental overhead artisi.
                    if len(_next_incr) < 0.02 * _func_count and len(_next_incr) > 0:
                        # Cok az dosya: yine de isle, hizi bozmaz
                        _incremental_files = _next_incr
                    elif len(_next_incr) > 0.80 * _func_count:
                        _incremental_files = None  # Full processing
                        logger.info(
                            "Incremental set too large (%d/%d > 80%%), falling back to full",
                            len(_next_incr), _func_count,
                        )
                    elif _next_incr:
                        _incremental_files = _next_incr
                    else:
                        _incremental_files = None  # Hic dosya bulunamadi, full

                    if _incremental_files is not None:
                        logger.info(
                            "Incremental set for iter %d: %d files "
                            "(%d newly named + 1-hop neighbors, %.1f%% of total)",
                            _pipeline_iter + 2, len(_incremental_files),
                            len(_newly_named),
                            100.0 * len(_incremental_files) / max(_func_count, 1),
                        )
                else:
                    # Yeni isim yok veya call graph yok → sonraki tur full
                    _incremental_files = None

                # v1.7.5: File cache — incremental modda sadece degisen dosyalari guncelle,
                # full modda tum cache'i yenile.
                if _incremental_files is not None:
                    # Sadece incremental dosyalari guncelle
                    for _cf in _incremental_files:
                        try:
                            _file_cache[_cf.name] = _cf.read_text(encoding="utf-8", errors="replace")
                        except Exception:
                            logger.debug("Dosya cache'e okunamadi, atlaniyor", exc_info=True)
                else:
                    _file_cache.clear()
                    _refresh_rglob_cache()
                    for _cf in _rglob_c_files if decompiled_dir.exists() else []:
                        try:
                            _file_cache[_cf.name] = _cf.read_text(encoding="utf-8", errors="replace")
                        except Exception:
                            logger.debug("Dosya cache'e okunamadi, atlaniyor", exc_info=True)
                context.metadata["file_cache"] = _file_cache  # type: ignore[attr-defined]
        # === v1.7.5: Pipeline feedback loop sonu ===

        stats["pipeline_iterations_run"] = len(_iteration_stats)
        stats["pipeline_iteration_details"] = _iteration_stats
        stats["timing_pipeline_loop"] = round(time.monotonic() - _loop_start, 1)
        logger.info(
            "Pipeline feedback loop: %d iterasyon, toplam %.1fs",
            len(_iteration_stats), time.monotonic() - _loop_start,
        )

        # === v1.10.0 M4 ESKI monolith entegrasyon: computation paketleri ===
        # HEM step registry HEM bu monolith yolu desteklenir (Berke karari).
        # Feature flag'ler kapaliysa hicbir is yapilmaz, davranis ayni kalir.
        # Sonuc: MaxSMT struct adaylari StructRecoveryEngine'e candidate olarak
        # iletilir; fusion/cfg_iso bilgileri NameMerger icin artifact'ta tutulur.
        _computation_struct_candidates: list = []
        _cfg_iso_matches_monolith: dict = {}
        _fused_matches_monolith: dict = {}

        # --- CFG Iso (assembly_analysis sonrasi zaten geldi; monolith yolunda
        # cfg_result su an mevcut degilse atla) ---
        _monolith_cfg_iso_enabled = getattr(
            context.config, "computation_recovery", None,
        ) and getattr(context.config.computation_recovery, "enable_cfg_iso", False)
        if _monolith_cfg_iso_enabled:
            try:
                from karadul.analyzers.cfg_analyzer import CFGAnalyzer
                from karadul.computation.cfg_iso import (
                    HybridCFGMatcher,
                    default_template_bank,
                )
                from karadul.pipeline.steps.cfg_iso_match import (
                    _ghidra_cfg_to_attributed,
                )

                _cfg_json_path = Path(cfg_json) if isinstance(cfg_json, (str, Path)) else None
                _cfg_iso_result = None
                if _cfg_json_path and _cfg_json_path.exists():
                    _cfg_iso_result = CFGAnalyzer().analyze(_cfg_json_path)
                if _cfg_iso_result and _cfg_iso_result.functions:
                    _matcher = HybridCFGMatcher(
                        config=context.config.computation_recovery,
                        templates=default_template_bank(),
                    )
                    _top_k = int(getattr(
                        context.config.computation_recovery,
                        "cfg_iso_top_k_candidates", 10,
                    ))
                    _min_conf = float(getattr(
                        context.config.computation_recovery,
                        "cfg_iso_min_confidence", 0.7,
                    ))
                    for _fn in _cfg_iso_result.functions:
                        _fn_addr = getattr(_fn, "address", None)
                        if not _fn_addr:
                            continue
                        try:
                            _attr = _ghidra_cfg_to_attributed(_fn)
                            if _attr.node_count() == 0:
                                continue
                            _top = _matcher.match(_attr, top_k=_top_k)
                            if _top and _top[0].confidence >= _min_conf:
                                _cfg_iso_matches_monolith[_fn_addr] = _top[0]
                        except Exception:
                            continue
                    stats["cfg_iso_matched_functions"] = len(_cfg_iso_matches_monolith)
                    logger.info(
                        "(monolith) CFG iso match: %d fonksiyon eslesti",
                        len(_cfg_iso_matches_monolith),
                    )
            except ImportError:
                logger.debug("(monolith) cfg_iso importable degil, atlaniyor")
            except Exception as _exc:
                logger.warning("(monolith) cfg_iso hatasi (atlaniyor): %s", _exc)

        # --- Signature Fusion (log-odds ensemble) ---
        _monolith_fusion_enabled = getattr(
            context.config, "computation", None,
        ) and getattr(
            context.config.computation, "enable_computation_fusion", False,
        )
        if _monolith_fusion_enabled:
            try:
                from karadul.computation.fusion import SignatureFuser
                from karadul.pipeline.steps.computation_fusion import (
                    _cfg_match_to_candidate,
                    _sig_match_to_candidate,
                )

                _fuser = SignatureFuser.from_computation_config(
                    context.config.computation,
                )
                _sig_by_key: dict = {}
                for _sm in (sig_matches or []):
                    _key = getattr(_sm, "original_name", None)
                    if not _key:
                        continue
                    _prev = _sig_by_key.get(_key)
                    if _prev is None or getattr(_sm, "confidence", 0.0) > getattr(
                        _prev, "confidence", 0.0,
                    ):
                        _sig_by_key[_key] = _sm
                _all_keys = set(_sig_by_key) | set(_cfg_iso_matches_monolith)
                for _key in _all_keys:
                    _cands = []
                    if _key in _sig_by_key:
                        _cands.append(_sig_match_to_candidate(_sig_by_key[_key]))
                    if _key in _cfg_iso_matches_monolith:
                        _cands.append(
                            _cfg_match_to_candidate(
                                _cfg_iso_matches_monolith[_key], _key,
                            ),
                        )
                    if _cands:
                        _fused_matches_monolith[_key] = _fuser.fuse(_cands)
                _n_accept = sum(
                    1 for _flist in _fused_matches_monolith.values()
                    for _fm in _flist if getattr(_fm, "decision", "") == "accept"
                )
                stats["computation_fusion_matches"] = len(_fused_matches_monolith)
                stats["computation_fusion_accepted"] = _n_accept
                logger.info(
                    "(monolith) computation fusion: %d fonksiyon, %d accept",
                    len(_fused_matches_monolith), _n_accept,
                )
            except ImportError:
                logger.debug("(monolith) computation fusion importable degil, atlaniyor")
            except Exception as _exc:
                logger.warning("(monolith) computation fusion hatasi (atlaniyor): %s", _exc)

        # --- MaxSMT Struct Recovery ---
        _monolith_struct_enabled = getattr(
            context.config, "computation", None,
        ) and getattr(
            context.config.computation,
            "enable_computation_struct_recovery", False,
        )
        if _monolith_struct_enabled and _pcode_result is not None:
            try:
                from karadul.computation.struct_recovery import StructLayoutSolver
                from karadul.pipeline.steps.computation_struct_recovery import (
                    _extract_accesses_from_pcode,
                )

                _accesses = _extract_accesses_from_pcode(_pcode_result)
                if _accesses:
                    _solver = StructLayoutSolver(context.config.computation)
                    _struct_result = _solver.solve_from_raw(
                        accesses=_accesses,
                        max_time_seconds=context.config.computation.struct_solver_timeout,
                    )
                    _computation_struct_candidates = list(
                        _struct_result.assigned_structs.values(),
                    )
                    stats["computation_struct_solved"] = len(
                        _computation_struct_candidates,
                    )
                    stats["computation_struct_confidence"] = round(
                        _struct_result.confidence, 3,
                    )
                    logger.info(
                        "(monolith) MaxSMT struct: %d aday (%.0f%% acilanmis)",
                        len(_computation_struct_candidates),
                        _struct_result.confidence * 100,
                    )
            except ImportError:
                logger.debug("(monolith) MaxSMT struct importable degil (z3 yok?)")
            except Exception as _exc:
                logger.warning("(monolith) MaxSMT struct hatasi (atlaniyor): %s", _exc)

        # --- Fusion accepted match'leri extracted_names'e enjekte et ---
        # NameMerger, `computation_fusion` source weight'i (0.90) ile bu
        # isimleri butunlestirir. Sadece decision == "accept" ve
        # calibrated_probability >= accept_threshold olanlar gecer.
        if _fused_matches_monolith and isinstance(extracted_names, dict):
            _added = 0
            for _key, _flist in _fused_matches_monolith.items():
                for _fm in _flist:
                    if getattr(_fm, "decision", "") != "accept":
                        continue
                    _new_name = getattr(_fm, "symbol_name", "") or ""
                    if not _new_name or _new_name == _key:
                        continue
                    # Onceden isimlendirilmis FUN_xxx'i ezme (yuksek guvenli).
                    if _key.startswith(("FUN_", "sub_", "thunk_")):
                        if _key not in extracted_names:
                            extracted_names[_key] = _new_name
                            _added += 1
            if _added > 0:
                stats["computation_fusion_injected"] = _added
                logger.info(
                    "(monolith) computation fusion extracted_names'e %d isim enjekte edildi",
                    _added,
                )

        # === v1.10.0 M4 ESKI monolith entegrasyon sonu ===

        # 3.1. Engineering Struct Recovery -- algoritma-bazli struct isimlendirme
        _step_start = time.monotonic()
        if context.config.binary_reconstruction.enable_struct_recovery and eng_result:
            try:
                from karadul.reconstruction.engineering import StructRecoveryEngine
                struct_engine = StructRecoveryEngine(context.config)

                # Algoritma bilgisini topla
                all_algos = _collect_all_algorithms(algo_result, eng_result)

                struct_dir = reconstructed_dir / "struct_recovered"
                struct_dir.mkdir(parents=True, exist_ok=True)

                # v1.5.2: Computation Recovery struct verilerini hazirla
                _comp_structs_for_eng = None
                if _computation_result and _computation_result.success:
                    _cs_layer = _computation_result.layer_results.get("constraint_solver")
                    if _cs_layer and hasattr(_cs_layer, "structs") and _cs_layer.structs:
                        _comp_structs_for_eng = [
                            s.to_dict() for s in _cs_layer.structs
                        ]

                # v1.10.0 M4 (Berke karari): MaxSMT kurtarma adaylarini
                # EKLE olarak StructRecoveryEngine'e gecir. Eski engine bu
                # candidate'lari kendi merge mantigiyla isler (computation
                # recovery struct'lari gibi best-effort aday seti).
                if _computation_struct_candidates:
                    _comp_structs_for_eng = list(_comp_structs_for_eng or [])
                    for _sc in _computation_struct_candidates:
                        try:
                            _comp_structs_for_eng.append({
                                "name": getattr(_sc, "name", "maxsmt_struct"),
                                "size": getattr(_sc, "size", 0),
                                "fields": [
                                    {
                                        "offset": getattr(_f, "offset", 0),
                                        "size": getattr(_f, "size", 0),
                                        "type_hint": getattr(_f, "type_hint", None),
                                    }
                                    for _f in getattr(_sc, "fields", [])
                                ],
                                "source": "computation_struct_recovery",
                            })
                        except Exception:
                            continue
                    logger.debug(
                        "StructRecoveryEngine'e %d MaxSMT candidate gecildi",
                        len(_computation_struct_candidates),
                    )

                struct_result = struct_engine.recover(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    ghidra_types_json=ghidra_types_json,
                    call_graph_json=call_graph_json,
                    output_dir=struct_dir,
                    algorithm_matches=all_algos,
                    computation_structs=_comp_structs_for_eng,
                )
                if struct_result.success:
                    stats["structs_enriched"] = struct_result.total_structs
                    stats["field_access_rewrites"] = struct_result.field_access_rewrites
                    if struct_result.types_header_path:
                        artifacts["enriched_types_header"] = struct_result.types_header_path
                    # Sonraki adimlar struct-recovered output'u kullansin
                    if struct_result.rewritten_files:
                        decompiled_dir = struct_dir
                    logger.info(
                        "Struct Recovery: %d struct, %d field rewrite",
                        struct_result.total_structs, struct_result.field_access_rewrites,
                    )
            except ImportError:
                logger.debug("StructRecoveryEngine bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Struct recovery hatasi (atlaniyor): %s", exc)
                errors.append(f"Struct recovery hatasi: {exc}")
        stats["timing_struct_recovery"] = round(time.monotonic() - _step_start, 1)

        # v1.10.0 M1 T3.5: Phase 3 — step registry runner2. 10 post-feedback
        # step'i calistir (inline_detection ... finalize). Eski Phase 3 kodu
        # (L3405-3933) bu branch aktifse tamamen atlanir. Finalize step'i
        # StageResult'i dondurur; biz stats/errors/artifacts'i merge edip
        # early return yapiyoruz.
        if _use_step_registry:
            from karadul.pipeline.runner import PipelineRunner

            # Feedback loop + struct_recovery sonrasi eski kod tarafindan
            # guncellenmis olan degiskenleri Phase 3 step'lerine seed olarak
            # aktar. Phase 3 runner'i bunlarin uzerine ek artifact yazar.
            _seed: dict[str, Any] = {
                "decompiled_dir": decompiled_dir,
                # semantic_naming -> flow_simplify -> comment_generation zinciri
                # decompiled_dir'i yeniden turev eder, ama baslangic kaynagini
                # struct_recovery ciktisindan alir. Dolayi ile bu key adi
                # semantic_naming'in requires listesinden hariç — seed zinciri
                # asagidan adim adim kuruluyor:
                "eng_result": eng_result,
                "algo_result": algo_result,
                "computation_result": _computation_result,
                "naming_result": naming_result,
                "functions_data": _func_data,
                "strings_data": _string_data,
                "call_graph_data": _call_graph_data,
                "sig_matches": sig_matches,
                # capa_annotation bu key'e ihtiyaç duyar; confidence_filter
                # zaten uretmisti ama step_ctx scope'undan ciktik, tekrar sun.
                "capa_capabilities": _capa_capabilities,
                # finalize pipeline suresini bilsin:
                "__pipeline_start": start,
                "__stage_name": self.name,
            }
            # Phase 1'den Phase 3'e dogrudan gecen path artifact'lari da seed'e
            # ekle (semantic_naming requires functions_json_path vb.).
            _seed.update({
                "functions_json_path": functions_json,
                "strings_json_path": strings_json,
                "call_graph_json_path": call_graph_json,
                "xrefs_json_path": xrefs_json,
            })
            # comment_generation'in giris dizini flow_simplify sonrasi; ancak
            # semantic_naming step'i bunu kendi uretiyor. İlk adim olan
            # inline_detection'a decompiled_dir key'i lazim (Phase 1'den
            # geldi); semantic_naming bunu tuketecek. Zincir temizlemek icin
            # bir baslangic artifact zincirini inject etmiyoruz — step'lerin
            # requires alanlari birbirine zincirli (semantic_naming_... ->
            # flow_simplify_... -> ...).

            try:
                runner_phase3 = PipelineRunner(steps=[
                    "inline_detection",
                    "semantic_naming",
                    "flow_simplify",
                    "comment_generation",
                    "capa_annotation",
                    "engineering_annotation",
                    "project_build",
                    "engineering_analysis",
                    "deep_tracing",
                    "finalize",
                ])
                step_ctx3 = runner_phase3.run(context, seed_artifacts=_seed)
            except RuntimeError as exc:
                return StageResult(
                    stage_name=self.name,
                    success=False,
                    duration_seconds=time.monotonic() - start,
                    errors=errors + [str(exc)],
                    stats=stats,
                    artifacts=artifacts,
                )

            # Phase 3 artifact'lari + shim'e yazilanlar birlikte topla.
            _stage_result: StageResult = step_ctx3.artifacts["stage_result"]
            # Phase 1/2 stats ve errors'i finalize'in ciktisiyla birlestir.
            _stage_result.stats = {**stats, **_stage_result.stats}
            _stage_result.errors = errors + _stage_result.errors
            _stage_result.artifacts = {**artifacts, **_stage_result.artifacts}
            _stage_result.success = len(_stage_result.artifacts) > 0
            return _stage_result

        # 3.5. Inline Function Detection -- compiler inline pattern'lerini tespit et
        #       abs(), strlen(), memcpy() vb. compiler tarafindan inline edilen
        #       fonksiyonlari regex ile bulup yorum olarak ekler.
        _step_start = time.monotonic()
        try:
            from karadul.analyzers.inline_detector import InlineDetector
            _refresh_rglob_cache()
            inline_c_files = list(_rglob_c_files) if decompiled_dir.exists() else []

            # v1.2.2: Seri dongu -> paralel (ThreadPoolExecutor)
            def _inline_detect_one(c_file: Path) -> int:
                """Tek dosyada inline pattern tespit et ve annotate et."""
                try:
                    _det = InlineDetector()  # Thread-safe: her thread kendi instance'i
                    # v1.9.2 QW5: _file_cache'den oku (disk I/O tekrari yok)
                    content = _file_cache.get(c_file.name) or c_file.read_text(encoding="utf-8", errors="replace")
                    matches = _det.detect_in_code(content)
                    if matches:
                        annotated = _det.annotate_code(content)
                        c_file.write_text(annotated, encoding="utf-8")
                        return len(matches)
                except Exception:
                    logger.debug("Crypto/obfuscation annotation basarisiz, atlaniyor", exc_info=True)
                return 0

            total_inline_detected = 0
            with ThreadPoolExecutor(max_workers=CPU_PERF_CORES) as _pool:
                for count in _pool.map(_inline_detect_one, inline_c_files):
                    total_inline_detected += count

            if total_inline_detected > 0:
                stats["inline_patterns_detected"] = total_inline_detected
                logger.info(
                    "Inline Detection: %d pattern tespit edildi (%d dosya, %d worker)",
                    total_inline_detected, len(inline_c_files), CPU_PERF_CORES,
                )
        except ImportError:
            logger.debug("InlineDetector bulunamadi, atlaniyor")
        except Exception as exc:
            logger.warning("Inline detection hatasi (atlaniyor): %s", exc)
        stats["timing_inline_detection"] = round(time.monotonic() - _step_start, 1)

        _step_start = time.monotonic()
        # 3.7. Semantic Parameter Naming -- algoritma-bazli parametre isimlendirme
        if context.config.binary_reconstruction.enable_semantic_naming and eng_result:
            try:
                from karadul.reconstruction.engineering import SemanticParameterNamer
                sem_namer = SemanticParameterNamer(context.config)

                all_algos = _collect_all_algorithms(algo_result, eng_result)

                sem_dir = reconstructed_dir / "semantic_named"
                sem_dir.mkdir(parents=True, exist_ok=True)

                sem_result = sem_namer.rename(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    call_graph_json=call_graph_json,
                    output_dir=sem_dir,
                    algorithm_matches=all_algos,
                    signature_matches=sig_matches if sig_matches else None,  # v1.7.2
                )
                if sem_result and sem_result.success:
                    stats["params_renamed"] = sem_result.total_renamed
                    # Sonraki adimlar semantic-named output'u kullansin
                    if sem_result.output_files:
                        decompiled_dir = sem_dir
                    logger.info(
                        "Semantic Naming: %d parametre yeniden isimlendi",
                        sem_result.total_renamed,
                    )
            except ImportError:
                logger.debug("SemanticParameterNamer bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Semantic naming hatasi (atlaniyor): %s", exc)
                errors.append(f"Semantic naming hatasi: {exc}")

        stats["timing_semantic_naming"] = round(time.monotonic() - _step_start, 1)

        # 3.6: Control Flow Simplification (v1.5.5)
        _step_start = time.monotonic()
        try:
            from karadul.reconstruction.c_flow_simplifier import CFlowSimplifier
            _flow_simplifier = CFlowSimplifier(context.config)
            _flow_result = _flow_simplifier.simplify_directory(decompiled_dir)
            stats["flow_gotos_eliminated"] = _flow_result.gotos_eliminated
            stats["flow_labels_renamed"] = _flow_result.labels_renamed
            stats["flow_labels_inlined"] = _flow_result.labels_inlined
            stats["flow_early_returns"] = _flow_result.early_returns
            stats["flow_breaks_continues"] = _flow_result.breaks_continues
            stats["flow_ifelse_restructured"] = _flow_result.ifelse_restructured
            stats["flow_cascading_collapsed"] = _flow_result.cascading_collapsed
            stats["flow_multi_target_inlined"] = _flow_result.multi_target_inlined
            logger.info(
                "Flow simplify: %d goto eliminated, %d label renamed, "
                "%d early_ret, %d break/cont, %d if-else, %d cascade, %d multi",
                _flow_result.gotos_eliminated, _flow_result.labels_renamed,
                _flow_result.early_returns, _flow_result.breaks_continues,
                _flow_result.ifelse_restructured, _flow_result.cascading_collapsed,
                _flow_result.multi_target_inlined,
            )
        except Exception as exc:
            logger.warning("Flow simplify hatasi: %s", exc)
        stats["timing_flow_simplify"] = round(time.monotonic() - _step_start, 1)

        context.report_progress("Comment Generation...", 0.75)
        # 4. Comment Generation
        _step_start = time.monotonic()
        if context.config.binary_reconstruction.enable_comment_generation:
            try:
                from karadul.reconstruction.c_comment_generator import CCommentGenerator
                commenter = CCommentGenerator(context.config)
                comment_dir = reconstructed_dir / "commented"
                comment_dir.mkdir(parents=True, exist_ok=True)
                comment_result = commenter.generate(
                    decompiled_dir=decompiled_dir,
                    output_dir=comment_dir,
                    functions_json=functions_json,
                    strings_json=strings_json,
                    call_graph_json=call_graph_json,
                    algorithm_results=(
                        algo_result.algorithms if algo_result else None
                    ),
                    cfg_matches=(
                        _computation_result.layer_results.get(
                            "cfg_fingerprint", {}
                        ).get("matches", [])
                        if _computation_result and _computation_result.success
                        else None
                    ),
                    formulas_extracted=(
                        _computation_result.layer_results.get(
                            "formula_extraction", {}
                        ).get("formulas", [])
                        if _computation_result and _computation_result.success
                        else None
                    ),
                )
                if comment_result.success:
                    stats["comments_added"] = comment_result.total_comments_added
                    stats["vuln_warnings"] = comment_result.vulnerability_warnings
                    stats["logic_comments"] = comment_result.logic_comments
                    stats["computation_annotations"] = comment_result.computation_annotations
                    artifacts["commented_sources"] = comment_dir
                    decompiled_dir = comment_dir
                    logger.info(
                        "Comments: %d yorum eklendi (%d guvenlik, %d logic, %d computation)",
                        comment_result.total_comments_added,
                        comment_result.vulnerability_warnings,
                        comment_result.logic_comments,
                        comment_result.computation_annotations,
                    )
                else:
                    errors.extend(comment_result.errors)
            except Exception as exc:
                logger.warning("Comment generation hatasi: %s", exc)
                errors.append(f"Comment generation hatasi: {exc}")

        stats["timing_comment_generation"] = round(time.monotonic() - _step_start, 1)

        # 4.2: CAPA capability annotasyonu -- fonksiyon basina @capability yorum ekle
        _step_start = time.monotonic()
        if _capa_capabilities and context.config.binary_reconstruction.enable_capa:
            try:
                _capa_comments_added = _inject_capa_comments(
                    decompiled_dir, _capa_capabilities, _func_data,
                )
                if _capa_comments_added > 0:
                    stats["capa_comments_added"] = _capa_comments_added
                    logger.info(
                        "CAPA: %d fonksiyona capability yorumu eklendi",
                        _capa_comments_added,
                    )
            except Exception as exc:
                logger.debug("CAPA comment injection hatasi: %s", exc)
        stats["timing_capa_comments"] = round(time.monotonic() - _step_start, 1)

        # 4.5. Engineering Block Annotation -- muhendislik blok yorumlari
        _step_start = time.monotonic()
        if context.config.binary_reconstruction.enable_block_annotation and eng_result:
            try:
                from karadul.reconstruction.engineering import CodeBlockAnnotator
                annotator = CodeBlockAnnotator(context.config)

                all_algos = _collect_all_algorithms(algo_result, eng_result)

                annotated_dir = reconstructed_dir / "annotated"
                annotated_dir.mkdir(parents=True, exist_ok=True)

                annot_result = annotator.annotate(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    call_graph_json=call_graph_json,
                    output_dir=annotated_dir,
                    algorithm_matches=all_algos,
                )
                if annot_result and annot_result.success:
                    stats["block_annotations"] = annot_result.total_annotations
                    stats["annotated_files"] = len(annot_result.annotated_files)
                    artifacts["annotated_sources"] = annotated_dir
                    # Sonraki adimlar annotated output'u kullansin
                    if annot_result.annotated_files:
                        decompiled_dir = annotated_dir
                    logger.info(
                        "Block Annotation: %d annotation, %d dosya",
                        annot_result.total_annotations, len(annot_result.annotated_files),
                    )
            except ImportError:
                logger.debug("CodeBlockAnnotator bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Block annotation hatasi (atlaniyor): %s", exc)
                errors.append(f"Block annotation hatasi: {exc}")

        stats["timing_block_annotation"] = round(time.monotonic() - _step_start, 1)

        context.report_progress("Project Build...", 0.85)
        # 5. Project Build — organize C proje ciktisi
        _step_start = time.monotonic()
        try:
            from karadul.reconstruction.c_project_builder import CProjectBuilder
            builder = CProjectBuilder(context.config)
            project_dir = reconstructed_dir / "project"
            build_result = builder.build(
                source_dir=decompiled_dir,
                output_dir=project_dir,
                workspace=context.workspace,
                algorithm_results=algo_result,
            )
            if build_result.success:
                stats["project_files"] = build_result.files_written
                artifacts["project_dir"] = project_dir
                logger.info("Project built: %d dosya", build_result.files_written)
        except Exception as exc:
            logger.warning("C project build hatasi: %s", exc)
            errors.append(f"C project build hatasi: {exc}")

        stats["timing_project_build"] = round(time.monotonic() - _step_start, 1)

        # 6. Engineering Analysis -- Domain Classification + Formula Reconstruction
        _step_start = time.monotonic()
        if (
            context.config.binary_reconstruction.enable_engineering_analysis
            and (algo_result or eng_result)
        ):
            try:
                from karadul.reconstruction.engineering import (
                    DomainClassifier,
                    FormulaReconstructor,
                )

                all_algo_list: list = []
                if algo_result and algo_result.success:
                    all_algo_list.extend(algo_result.algorithms)
                if eng_result and eng_result.success:
                    all_algo_list.extend(eng_result.algorithms)

                # Domain Classification
                # v1.4.2: Binary-level domain override -- BLAS/ML sembol tespiti
                # v1.4.3: Indicator listesi c_algorithm_id.BLAS_ML_INDICATORS'dan import edilir
                from karadul.reconstruction.c_algorithm_id import BLAS_ML_INDICATORS
                _binary_hints = None
                if _func_data:
                    for _fn in _func_data:
                        _fn_lower = _fn.lower() if isinstance(_fn, str) else ""
                        if any(ind in _fn_lower for ind in BLAS_ML_INDICATORS):
                            _binary_hints = {"domain_override": "ml"}
                            logger.info(
                                "Binary domain override: ml (indicator in '%s')", _fn,
                            )
                            break

                # v1.4.3: dynamic_libraries.json'dan domain hint (stripped binary fallback)
                if not _binary_hints:
                    _dyn_libs_path = static_dir / "dynamic_libraries.json"
                    if _dyn_libs_path.exists():
                        try:
                            _dyn_data = json.loads(_dyn_libs_path.read_text())
                            _libs = _dyn_data.get("libraries", [])
                            _lib_str = " ".join(
                                str(l.get("path", l) if isinstance(l, dict) else l).lower()
                                for l in _libs
                            )
                            _ML_LIB_INDICATORS = {
                                "blas", "lapack", "accelerate", "openblas",
                                "mkl", "cublas", "veclib",
                            }
                            if any(ind in _lib_str for ind in _ML_LIB_INDICATORS):
                                _binary_hints = {"domain_override": "ml"}
                                logger.info(
                                    "Binary domain override from dynamic_libraries: ml",
                                )
                        except Exception:
                            logger.debug("Binary domain override tespiti basarisiz, atlaniyor", exc_info=True)

                # v1.4.3: String verisini DomainClassifier'a gecir
                _domain_strings = None
                if _string_data:
                    if isinstance(_string_data, list):
                        _domain_strings = _string_data
                    elif isinstance(_string_data, dict):
                        _raw_strings = _string_data.get(
                            "strings", list(_string_data.values()),
                        )
                        _domain_strings = [
                            s["value"] if isinstance(s, dict) else str(s)
                            for s in _raw_strings
                        ]

                domain_clf = DomainClassifier()
                domain_report = domain_clf.classify(
                    algorithms=all_algo_list,
                    strings=_domain_strings,
                    binary_hints=_binary_hints,
                )

                # Formula Reconstruction
                formula_rec = FormulaReconstructor()
                formulas = formula_rec.reconstruct(all_algo_list)

                # Sonuclari kaydet -- JSON
                eng_analysis = {
                    "domain_classification": domain_report.to_dict(),
                    "formulas": [f.to_dict() for f in formulas],
                    "total_formulas": len(formulas),
                }
                if domain_report.domain_summary:
                    eng_analysis["primary_domain"] = max(
                        domain_report.domain_summary, key=domain_report.domain_summary.get,
                    )

                # v1.5.2: Computation fusion identifications'i engineering
                # analysis'a ekle.  Signature Fusion hangi fonksiyonlarin
                # hangi library/algorithm'den geldigini Dempster-Shafer ile
                # birlestirip kesinlestiriyor -- bu bilgi domain classification
                # ile birlikte raporlanmali.
                if _computation_result and _computation_result.success:
                    _fusion_layer = _computation_result.layer_results.get(
                        "signature_fusion", {},
                    )
                    if isinstance(_fusion_layer, dict):
                        _fusion_ids = _fusion_layer.get("identifications", {})
                        if _fusion_ids:
                            eng_analysis["computation_fusion_identifications"] = _fusion_ids
                            eng_analysis["computation_fusion_count"] = len(_fusion_ids)
                eng_json_path = context.workspace.save_json(
                    "reconstructed", "engineering_analysis", eng_analysis,
                )
                artifacts["engineering_analysis"] = eng_json_path

                # Sonuclari kaydet -- Markdown raporu
                md_report = formula_rec.generate_report(formulas)
                md_path = reconstructed_dir / "engineering_analysis.md"
                md_path.write_text(md_report, encoding="utf-8")
                artifacts["engineering_analysis_md"] = md_path

                stats["engineering_domains"] = len(domain_report.domain_summary)
                stats["engineering_formulas"] = len(formulas)
                logger.info(
                    "Engineering Analysis: %d domain, %d formula",
                    len(domain_report.domain_summary), len(formulas),
                )
            except ImportError:
                logger.debug("Engineering analysis modulleri bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Engineering analysis hatasi (atlaniyor): %s", exc)
                errors.append(f"Engineering analysis hatasi: {exc}")

        stats["timing_engineering_analysis"] = round(time.monotonic() - _step_start, 1)

        context.report_progress("Deep Algorithm Tracing...", 0.95)
        # 7. Deep Algorithm Tracing (v1.1.5) -- dispatch resolution, data flow, composition, call chain
        _step_start = time.monotonic()
        dispatch_result = None
        data_flow_result = None
        augmented_cg_json = None  # v1.2: dispatch resolver augmented call graph

        if context.config.binary_reconstruction.enable_engineering_analysis:
            # 7.1 Virtual Dispatch Resolution (ObjC/Swift/C++)
            try:
                from karadul.reconstruction.engineering import VirtualDispatchResolver
                dispatch_resolver = VirtualDispatchResolver()
                dispatch_result = dispatch_resolver.resolve(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    call_graph_json=call_graph_json,
                    strings_json=strings_json,
                )
                if dispatch_result and dispatch_result.success:
                    stats["dispatch_sites"] = dispatch_result.total_dispatch_sites
                    stats["dispatch_resolved"] = dispatch_result.resolved_count
                    stats["dispatch_resolution_rate"] = f"{dispatch_result.resolution_rate:.1%}"
                    context.workspace.save_json(
                        "reconstructed", "dispatch_resolution", dispatch_result.to_dict(),
                    )
                    logger.info(
                        "Dispatch Resolution: %d/%d resolved (%.1f%%)",
                        dispatch_result.resolved_count,
                        dispatch_result.total_dispatch_sites,
                        dispatch_result.resolution_rate * 100,
                    )
                    # v1.2: Augmented call graph olustur — downstream moduller bunu kullanacak
                    if dispatch_result.augmented_edges:
                        # v1.2.2: _call_graph_data cache'den deep copy al
                        original_cg = copy.deepcopy(_call_graph_data) if _call_graph_data else {}
                        # Augmented edges'i merge et
                        if "edges" not in original_cg:
                            original_cg["edges"] = []
                        for edge in dispatch_result.augmented_edges:
                            original_cg["edges"].append(edge)
                        # Kaydet
                        augmented_cg_path = reconstructed_dir / "augmented_call_graph.json"
                        augmented_cg_path.write_text(
                            json.dumps(original_cg, indent=2), encoding="utf-8",
                        )
                        augmented_cg_json = augmented_cg_path
                        logger.info(
                            "Augmented CG: %d yeni edge eklendi",
                            len(dispatch_result.augmented_edges),
                        )
            except ImportError:
                logger.debug("VirtualDispatchResolver bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Dispatch resolution hatasi (atlaniyor): %s", exc)
                errors.append(f"Dispatch resolution hatasi: {exc}")

            # 7.2 Inter-Procedural Data Flow
            try:
                from karadul.reconstruction.engineering import InterProceduralDataFlow
                data_flow_analyzer = InterProceduralDataFlow()
                data_flow_dir = reconstructed_dir / "data_flow"
                data_flow_dir.mkdir(parents=True, exist_ok=True)
                data_flow_result = data_flow_analyzer.analyze(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    call_graph_json=augmented_cg_json or call_graph_json,
                    xrefs_json=xrefs_json if xrefs_json.exists() else None,
                    output_dir=data_flow_dir,
                )
                if data_flow_result and data_flow_result.success:
                    stats["data_flow_edges"] = data_flow_result.total_edges
                    stats["data_flow_pipelines"] = len(data_flow_result.pipelines)
                    logger.info(
                        "Data Flow: %d edges, %d pipelines",
                        data_flow_result.total_edges, len(data_flow_result.pipelines),
                    )
            except ImportError:
                logger.debug("InterProceduralDataFlow bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Data flow analysis hatasi (atlaniyor): %s", exc)
                errors.append(f"Data flow hatasi: {exc}")

            # 7.2.5 Inter-Procedural Parameter Name Propagation (sig_matches seed'li)
            try:
                from karadul.reconstruction.engineering import InterProceduralDataFlow
                _param_prop_analyzer = InterProceduralDataFlow()
                _param_prop_result = _param_prop_analyzer.propagate_param_names(
                    decompiled_dir=decompiled_dir,
                    functions_json=functions_json,
                    call_graph_json=augmented_cg_json or call_graph_json,
                    signature_matches=sig_matches if sig_matches else None,
                )
                if _param_prop_result:
                    stats["param_names_propagated"] = len(_param_prop_result)
                    logger.info(
                        "Param name propagation: %d isim yayildi",
                        len(_param_prop_result),
                    )
            except ImportError:
                logger.debug("InterProceduralDataFlow (param propagation) bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Param name propagation hatasi (atlaniyor): %s", exc)
                errors.append(f"Param name propagation hatasi: {exc}")

            # v1.2: call graph ve algoritma listesini try disinda hazirla (7.3 + 7.4 paylasir)
            all_algos = _collect_all_algorithms(algo_result, eng_result)

            # v1.2.2: augmented varsa onu oku (yeni dosya), yoksa cache'den al
            if augmented_cg_json and augmented_cgjson.exists():
                call_graph_data = json.loads(augmented_cgjson.read_text(errors="replace"))
            else:
                call_graph_data = _call_graph_data or {}

            # 7.3 Algorithm Composition Analysis
            logger.info("Step 7.3: Algorithm Composition Analysis basliyor (%d node, %d edge)",
                        len(call_graph_data) if call_graph_data else 0,
                        sum(len(v) if isinstance(v, list) else 0 for v in (call_graph_data or {}).values()))
            try:
                from karadul.reconstruction.engineering import AlgorithmCompositionAnalyzer

                comp_analyzer = AlgorithmCompositionAnalyzer()
                comp_result = comp_analyzer.analyze(
                    call_graph=call_graph_data,
                    algorithms=all_algos,
                    data_flow=data_flow_result,
                    dispatch_result=dispatch_result,
                )
                if comp_result and comp_result.success:
                    stats["compositions"] = comp_result.total_compositions
                    context.workspace.save_json(
                        "reconstructed", "algorithm_compositions", comp_result.to_dict(),
                    )
                    comp_md = comp_analyzer.generate_report(comp_result)
                    comp_md_path = reconstructed_dir / "compositions.md"
                    comp_md_path.write_text(comp_md, encoding="utf-8")
                    artifacts["compositions"] = comp_md_path
                    logger.info("Compositions: %d found", comp_result.total_compositions)
            except ImportError:
                logger.debug("AlgorithmCompositionAnalyzer bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Composition analysis hatasi (atlaniyor): %s", exc)
                errors.append(f"Composition analysis hatasi: {exc}")

            # 7.4 Deep Call Chain Tracing
            logger.info("Step 7.4: Deep Call Chain Tracing basliyor (max_depth=8, max_targets=3)")
            try:
                from karadul.reconstruction.engineering import DeepCallChainTracer
                # v1.2.3: max_depth 10->8, max_targets 5->3 (performance)
                tracer = DeepCallChainTracer(max_depth=8, max_targets=3)
                trace_results = tracer.trace_auto(
                    call_graph=call_graph_data if call_graph_data else {},
                    algorithms=all_algos if all_algos else None,
                    dispatch_result=dispatch_result,
                    top_n=3,
                )
                if trace_results:
                    stats["trace_targets"] = len(trace_results)
                    stats["trace_total_nodes"] = sum(t.total_nodes for t in trace_results)
                    trace_md = tracer.generate_report(trace_results)
                    trace_md_path = reconstructed_dir / "call_traces.md"
                    trace_md_path.write_text(trace_md, encoding="utf-8")
                    artifacts["call_traces"] = trace_md_path
                    logger.info(
                        "Deep Trace: %d targets, %d total nodes",
                        len(trace_results),
                        sum(t.total_nodes for t in trace_results),
                    )
            except ImportError:
                logger.debug("DeepCallChainTracer bulunamadi, atlaniyor")
            except Exception as exc:
                logger.warning("Deep trace hatasi (atlaniyor): %s", exc)
                errors.append(f"Deep trace hatasi: {exc}")

        stats["timing_deep_tracing"] = round(time.monotonic() - _step_start, 1)

        duration = time.monotonic() - start
        success = len(artifacts) > 0

        # v1.2.2: Toplam timing ozeti
        _timing_keys = [k for k in stats if k.startswith("timing_")]
        _timing_total = sum(stats[k] for k in _timing_keys)
        logger.info(
            "Binary reconstruction: %d artifact, %.1fs (step toplami %.1fs), %d hata",
            len(artifacts), duration, _timing_total, len(errors),
        )
        for _tk in sorted(_timing_keys):
            logger.debug("  %s: %.1fs", _tk, stats[_tk])

        return StageResult(
            stage_name=self.name,
            success=success,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def _execute_js(self, context: PipelineContext, start: float) -> StageResult:
        """JS reconstruction pipeline (mevcut kod)."""
        errors: list[str] = []
        artifacts: dict[str, Path] = {}
        stats: dict = {}

        from karadul.reconstruction.variable_renamer import VariableRenamer
        from karadul.reconstruction.module_splitter import ModuleSplitter
        from karadul.reconstruction.type_inferrer import TypeInferrer
        from karadul.reconstruction.comment_generator import CommentGenerator
        from karadul.reconstruction.gap_filler import GapFiller
        from karadul.reconstruction.project_builder import ProjectBuilder

        reconstructed_dir = context.workspace.get_stage_dir("reconstructed")
        deob_dir = context.workspace.get_stage_dir("deobfuscated")

        # Kaynak dosya: deobfuscated cikti
        source_files = sorted(deob_dir.rglob("*.js"))
        if not source_files:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=["Deobfuscate edilmis dosya bulunamadi"],
            )

        # En buyuk dosyayi ana kaynak olarak sec
        main_source = max(source_files, key=lambda f: f.stat().st_size)
        stats["source_file"] = main_source.name
        stats["source_size"] = main_source.stat().st_size

        # 1. Context-Aware Variable Renaming (NSA-grade)
        #    Eski VariableRenamer yerine ContextNamer kullan -- 300+ kural,
        #    3-seviye data flow tracking, confidence scoring
        context.report_progress("Step 1/7: Context-Aware Variable Naming", 0.0)
        from karadul.reconstruction.context_namer import ContextNamer
        context_namer = ContextNamer(context.config)
        renamed_file = reconstructed_dir / f"{main_source.stem}.nsa_named.js"

        try:
            naming_result = context_namer.analyze_and_rename(main_source, renamed_file)
            if naming_result.success and naming_result.output_file:
                artifacts["renamed"] = naming_result.output_file
                stats["variables_renamed"] = naming_result.variables_renamed
                stats["rename_mappings"] = len(naming_result.mappings)
                stats["rename_high_confidence"] = naming_result.high_confidence
                stats["rename_medium_confidence"] = naming_result.medium_confidence
                stats["rename_low_confidence"] = naming_result.low_confidence
                current_file = naming_result.output_file
            else:
                errors.extend(naming_result.errors)
                current_file = main_source
                # Fallback: eski VariableRenamer dene
                logger.info("ContextNamer basarisiz, VariableRenamer fallback")
                renamer = VariableRenamer(context.config)
                fallback_file = reconstructed_dir / f"{main_source.stem}.renamed.js"
                try:
                    fallback_result = renamer.rename(main_source, fallback_file)
                    if fallback_result.success and fallback_result.output_file:
                        artifacts["renamed"] = fallback_result.output_file
                        stats["variables_renamed"] = fallback_result.variables_renamed
                        stats["rename_mappings"] = len(fallback_result.mappings)
                        current_file = fallback_result.output_file
                except Exception:
                    logger.debug("Context naming fallback basarisiz, atlaniyor", exc_info=True)
        except Exception as exc:
            logger.warning("Context naming hatasi: %s", exc)
            errors.append(f"Context naming hatasi: {exc}")
            current_file = main_source

        # 1.5. LLM-Assisted Variable Naming (opsiyonel -- --use-llm flag ile)
        context.report_progress("Step 2/7: LLM-Assisted Naming", 0.15)
        #      ContextNamer'in dusuk-confidence biraktigi degiskenleri Claude CLI ile
        #      isimlendirir. context_json bilgisi varsa onu kullanir.
        if context.config.analysis.use_llm_naming:
            from karadul.reconstruction.naming.llm_naming import ClaudeLLMNamer
            llm_namer = ClaudeLLMNamer(
                context.config,
                model=context.config.analysis.llm_model,
            )
            if llm_namer.is_available:
                try:
                    # ContextNamer'in context_json'unu kullan
                    context_json_data = None
                    if naming_result is not None and hasattr(naming_result, 'context_json'):
                        context_json_data = naming_result.context_json

                    if context_json_data:
                        # Context JSON'u gecici dosyaya yaz.
                        # v1.10.0 Fix Sprint MED-5: llm_ctx_path'i try dışında
                        # tanımla, json.dump exception atarsa finally'de
                        # NameError vermemesi icin.
                        import tempfile
                        llm_ctx_path = None
                        try:
                            with tempfile.NamedTemporaryFile(
                                suffix=".json", prefix="bw_llm_ctx_",
                                delete=False, mode="w",
                            ) as tmp:
                                json.dump(context_json_data, tmp, ensure_ascii=False)
                                llm_ctx_path = Path(tmp.name)

                            llm_result = llm_namer.name_variables(
                                llm_ctx_path, current_file,
                            )
                            if llm_result.success and llm_result.total_named > 0:
                                stats["llm_variables_named"] = llm_result.total_named
                                stats["llm_model"] = llm_result.model_used
                                stats["llm_batches"] = llm_result.total_batches
                                stats["llm_failed_batches"] = llm_result.failed_batches
                                logger.info(
                                    "LLM naming: %d degisken isimlendirildi (%s)",
                                    llm_result.total_named, llm_result.model_used,
                                )
                                # LLM mappings'i context_json'a merge et
                                # (sonraki apply adiminda kullanilmak uzere)
                                for scope_id, scope_mappings in llm_result.mappings.items():
                                    for old_name, new_name in scope_mappings.items():
                                        logger.info(
                                            "  LLM: %s::%s -> %s",
                                            scope_id, old_name, new_name,
                                        )
                            else:
                                errors.extend(llm_result.errors)
                        finally:
                            if llm_ctx_path is not None:
                                llm_ctx_path.unlink(missing_ok=True)
                    else:
                        logger.info(
                            "LLM naming: context_json mevcut degil, atlaniyor"
                        )
                except Exception as exc:
                    logger.warning("LLM naming hatasi: %s", exc)
                    errors.append(f"LLM naming hatasi: {exc}")
            else:
                logger.warning(
                    "LLM naming istendi ama Claude CLI bulunamadi"
                )

        context.report_progress("Step 3/7: Parameter Recovery", 0.25)
        # 1.8. Param Recovery (this.X=param, call-site, destructuring)
        #      ContextNamer degisken isimlerini verdi, simdi fonksiyon
        #      parametrelerini de kurtariyoruz. 5 strateji ile LLM-siz
        #      parametre ismi recovery.
        from karadul.reconstruction.param_recovery import ParamRecovery
        param_recovery = ParamRecovery(context.config)

        try:
            param_result = param_recovery.recover(current_file)
            if param_result.success and param_result.recovered > 0:
                param_output = reconstructed_dir / f"{current_file.stem}.params.js"
                try:
                    applied = param_recovery.apply_to_file(
                        current_file, param_result.recovery_json, param_output,
                    )
                    if applied > 0 and param_output.exists():
                        artifacts["param_recovered"] = param_output
                        stats["params_recovered"] = param_result.recovered
                        stats["params_high_quality"] = param_result.high_quality
                        stats["params_recovery_rate"] = param_result.recovery_rate
                        stats["params_by_strategy"] = param_result.by_strategy
                        stats["params_applied"] = applied
                        current_file = param_output
                        logger.info(
                            "ParamRecovery: %d recovered, %d applied (rate=%s)",
                            param_result.recovered, applied,
                            param_result.recovery_rate,
                        )
                    else:
                        errors.extend(param_result.errors)
                except Exception as apply_exc:
                    logger.warning("ParamRecovery apply hatasi: %s", apply_exc)
                    errors.append(f"ParamRecovery apply hatasi: {apply_exc}")
            elif param_result.success:
                logger.info("ParamRecovery: 0 parametre bulundu, atlaniyor")
                stats["params_recovered"] = 0
            else:
                errors.extend(param_result.errors)
        except Exception as exc:
            logger.warning("ParamRecovery hatasi: %s", exc)
            errors.append(f"ParamRecovery hatasi: {exc}")

        context.report_progress("Step 4/7: Module Splitting", 0.40)
        # 2. Module Splitting (webpack modulleri varsa)
        splitter = ModuleSplitter(context.config)
        webpack_dir = deob_dir / "webpack_modules"
        split_result = None

        if webpack_dir.exists() and any(webpack_dir.glob("module_*.js")):
            modules_output = reconstructed_dir / "modules"
            try:
                split_result = splitter.split(webpack_dir, modules_output)
                if split_result.success:
                    stats["modules_split"] = split_result.total_modules
                    stats["module_categories"] = split_result.categorized
                    if split_result.output_dir:
                        artifacts["modules_dir"] = split_result.output_dir
                else:
                    errors.extend(split_result.errors)
            except Exception as exc:
                logger.warning("Module splitting hatasi: %s", exc)
                errors.append(f"Module splitting hatasi: {exc}")

        # 2.5. Naming Pipeline + Source Matching (webpack modulleri varsa)
        #      NamingPipeline config ile olusturulursa source matching otomatik aktif.
        #      Pipeline sirasi: npm fingerprint -> source match (orijinal kaynak indirip
        #      fonksiyon eslestirme) -> structural -> llm -> conflict resolution.
        #      Source match sonuclari apply() sirasinda JS dosyalarina uygulanir:
        #      minified degisken isimleri (e, t, n, r) orijinale cevrilir.
        modules_subdir = deob_dir / "webpack_modules" / "modules"
        if modules_subdir.exists() and any(modules_subdir.glob("*.js")):
            from karadul.reconstruction.naming import NamingPipeline
            try:
                naming_pipeline = NamingPipeline(
                    config=context.config,
                    use_codex=False,
                )
                naming_manifest = naming_pipeline.run(modules_subdir)
                named_output = reconstructed_dir / "named_project"
                naming_pipeline.apply(modules_subdir, named_output, naming_manifest)
                naming_summary = naming_manifest.summary()
                stats["naming_total"] = naming_summary["total_named"]
                stats["naming_by_source"] = naming_summary["by_source"]
                stats["naming_avg_confidence"] = naming_summary["avg_confidence"]
                artifacts["named_project"] = named_output
                artifacts["naming_manifest"] = named_output / "naming-manifest.json"

                # Source match istatistikleri
                sm_stats = naming_summary.get("statistics", {}).get("source_match")
                if sm_stats:
                    stats["source_match_names_recovered"] = sm_stats.get("names_recovered", 0)
                    stats["source_match_functions_matched"] = sm_stats.get("functions_matched", 0)
                    stats["source_match_packages_resolved"] = sm_stats.get("packages_resolved", 0)
                sm_mappings = getattr(naming_manifest, "source_match_mappings", {})
                if sm_mappings:
                    total_renames = sum(len(m) for m in sm_mappings.values())
                    stats["source_match_total_renames"] = total_renames
                    logger.info(
                        "Source matching: %d modul, %d toplam rename",
                        len(sm_mappings), total_renames,
                    )

                logger.info(
                    "NamingPipeline: %d modul isimlendirildi (conf=%.3f)",
                    naming_summary["total_named"],
                    naming_summary["avg_confidence"],
                )
            except Exception as exc:
                logger.warning("NamingPipeline hatasi: %s", exc)
                errors.append(f"NamingPipeline hatasi: {exc}")

        context.report_progress("Step 5/7: Type Inference", 0.60)
        # 3. Type Inference
        inferrer = TypeInferrer(context.config)
        typed_file = reconstructed_dir / f"{current_file.stem}.typed.js"
        try:
            infer_result = inferrer.infer(current_file, typed_file)
            if infer_result.success and infer_result.output_file:
                artifacts["typed"] = infer_result.output_file
                stats["functions_annotated"] = infer_result.functions_annotated
                current_file = infer_result.output_file
            else:
                errors.extend(infer_result.errors)
        except Exception as exc:
            logger.warning("Type inference hatasi: %s", exc)
            errors.append(f"Type inference hatasi: {exc}")

        context.report_progress("Step 6/7: Comment Generation", 0.75)
        # 4. Comment Generation
        commenter = CommentGenerator(context.config)
        commented_file = reconstructed_dir / f"{current_file.stem}.commented.js"
        try:
            comments_added = commenter.generate(current_file, commented_file)
            if comments_added > 0 and commented_file.exists():
                artifacts["commented"] = commented_file
                stats["comments_added"] = comments_added
                current_file = commented_file
        except Exception as exc:
            logger.warning("Comment generation hatasi: %s", exc)
            errors.append(f"Comment generation hatasi: {exc}")

        # 5. Gap Filling
        filler = GapFiller(context.config)
        try:
            gap_result = filler.fill(context.workspace)
            if gap_result.success:
                stats["dead_code_count"] = len(gap_result.dead_code_functions)
                stats["missing_imports"] = len(gap_result.missing_imports)
                stats["api_endpoints"] = len(gap_result.api_endpoints)
                stats["env_variables"] = len(gap_result.env_variables)
            errors.extend(gap_result.errors)
        except Exception as exc:
            logger.warning("Gap filling hatasi: %s", exc)
            errors.append(f"Gap filling hatasi: {exc}")
            gap_result = None

        context.report_progress("Step 7/7: Project Building", 0.90)
        # 6. Project Building
        #    ProjectReconstructor: 10+ modul varsa gercek proje yapisi olustur
        #    ProjectBuilder: fallback (az modul veya reconstructor devre disi)
        use_reconstructor = (
            self._use_project_reconstructor
            and split_result is not None
            and hasattr(split_result, "total_modules")
            and split_result.total_modules >= 10
        )

        if use_reconstructor:
            from karadul.reconstruction.project_reconstructor import ProjectReconstructor
            reconstructor = ProjectReconstructor(context.config)
            try:
                recon_result = reconstructor.reconstruct(
                    context.workspace, context.target,
                )
                if recon_result.success:
                    stats["project_files"] = recon_result.files_written
                    stats["dependencies"] = len(recon_result.dependencies)
                    stats["categories"] = recon_result.categories
                    stats["reconstruction_mode"] = "project_reconstructor"
                    if recon_result.project_dir:
                        artifacts["project_dir"] = recon_result.project_dir
                    if recon_result.package_json:
                        artifacts["package_json"] = recon_result.package_json
                    if recon_result.entry_point:
                        artifacts["entry_point"] = recon_result.entry_point
                    if recon_result.stats.get("validation"):
                        stats["validation"] = recon_result.stats["validation"]
                errors.extend(recon_result.errors)
            except Exception as exc:
                logger.warning("ProjectReconstructor hatasi, fallback: %s", exc)
                errors.append(f"ProjectReconstructor hatasi: {exc}")
                use_reconstructor = False  # Fallback to ProjectBuilder

        if not use_reconstructor:
            from karadul.reconstruction.dependency_resolver import DependencyResolver
            dep_resolver = DependencyResolver(context.config, verify_npm=False)
            builder = ProjectBuilder(context.config, dependency_resolver=dep_resolver)
            try:
                build_result = builder.build(
                    context.workspace, context.target,
                    split_result=split_result,
                    gap_result=gap_result,
                )
                if build_result.success:
                    stats["project_files"] = build_result.files_created
                    stats["dependencies"] = len(build_result.dependencies)
                    stats["reconstruction_mode"] = "project_builder"
                    if build_result.project_dir:
                        artifacts["project_dir"] = build_result.project_dir
                    if build_result.package_json:
                        artifacts["package_json"] = build_result.package_json
                    if build_result.entry_point:
                        artifacts["entry_point"] = build_result.entry_point
                errors.extend(build_result.errors)
            except Exception as exc:
                logger.warning("Project build hatasi: %s", exc)
                errors.append(f"Project build hatasi: {exc}")

        duration = time.monotonic() - start
        # En az bir adim basarili ise success
        success = len(artifacts) > 0

        logger.info(
            "Reconstruction: %d artifact, %.1fs",
            len(artifacts), duration,
        )

        return StageResult(
            stage_name=self.name,
            success=success,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )


class ReportStage(Stage):
    """Raporlama stage'i -- JSON, Markdown ve HTML rapor uretir.

    Her uc reporter'i calistirir ve sonuclari workspace/reports/ altina kaydeder.
    Eksik stage verileri varsa kismi rapor uretilir (N/A degerlerle).
    """

    name = "report"
    requires = ["identify"]  # static opsiyonel -- basarisiz olsa bile rapor uretilmeli

    def execute(self, context: PipelineContext) -> StageResult:
        """Uc formatta rapor uret."""
        start = time.monotonic()
        errors: list[str] = []
        artifacts: dict[str, Path] = {}

        # PipelineResult olustur (context'teki sonuclardan)
        from karadul.core.result import PipelineResult

        pipeline_result = PipelineResult(
            target_name=context.target.name,
            target_hash=context.target.file_hash,
            workspace_path=context.workspace.path,
        )

        # Onceki stage sonuclarini ekle
        for stage_name, stage_result in context.results.items():
            pipeline_result.add_stage_result(stage_result)

        pipeline_result.total_duration = sum(
            sr.duration_seconds for sr in context.results.values()
        )

        # JSON rapor
        logger.info("Report: JSON rapor olusturuluyor...")
        try:
            from karadul.reporting.json_report import JSONReporter
            json_path = JSONReporter().generate(pipeline_result, context.workspace)
            artifacts["report_json"] = json_path
        except Exception as exc:
            logger.exception("JSON rapor olusturulamadi: %s", exc)
            errors.append(f"JSON rapor hatasi: {exc}")

        # Markdown rapor
        logger.info("Report: Markdown rapor olusturuluyor...")
        try:
            from karadul.reporting.markdown_report import MarkdownReporter
            md_path = MarkdownReporter().generate(pipeline_result, context.workspace)
            artifacts["report_md"] = md_path
        except Exception as exc:
            logger.exception("Markdown rapor olusturulamadi: %s", exc)
            errors.append(f"Markdown rapor hatasi: {exc}")

        # HTML rapor
        logger.info("Report: HTML rapor olusturuluyor...")
        try:
            from karadul.reporting.html_report import HTMLReporter
            html_path = HTMLReporter().generate(pipeline_result, context.workspace)
            artifacts["report_html"] = html_path
        except Exception as exc:
            logger.exception("HTML rapor olusturulamadi: %s", exc)
            errors.append(f"HTML rapor hatasi: {exc}")

        # SARIF rapor (v1.2.8+)
        try:
            from karadul.reporting.sarif_report import SARIFReporter
            sarif_path = SARIFReporter().generate(pipeline_result, context.workspace)
            artifacts["report_sarif"] = sarif_path
        except ImportError:
            logger.debug("SARIFReporter bulunamadi, atlaniyor")
        except Exception as exc:
            logger.exception("SARIF rapor olusturulamadi: %s", exc)
            errors.append(f"SARIF rapor hatasi: {exc}")

        # En az bir rapor uretilebildiyse basarili say
        success = len(artifacts) > 0

        stats = {
            "reports_generated": len(artifacts),
            "formats": list(artifacts.keys()),
        }

        return StageResult(
            stage_name=self.name,
            success=success,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )


# -----------------------------------------------------------------------
# CAPA comment injection helper (module-level, stages.py icin)
# -----------------------------------------------------------------------

def _inject_capa_comments(
    decompiled_dir: Path,
    capa_capabilities: dict[str, list[dict]],
    func_data: dict | None,
) -> int:
    """CAPA capability bilgisini decompile edilmis C dosyalarina yorum olarak ekle.

    Her fonksiyonun basina /** @capability ... */ blogu ekler.

    Args:
        decompiled_dir: Decompile edilmis (veya comment pass'ten gecmis) C dosyalari.
        capa_capabilities: {addr_hex: [{name, namespace, ...}, ...]}
        func_data: Ghidra functions.json (fonksiyon adresi -> isim mapping icin).

    Returns:
        Yorum eklenen fonksiyon sayisi.
    """
    if not decompiled_dir or not decompiled_dir.exists():
        return 0
    if not capa_capabilities:
        return 0

    # Ghidra functions.json'dan adres -> fonksiyon ismi mapping olustur
    addr_to_name: dict[str, str] = {}
    name_to_caps: dict[str, list[str]] = {}

    if func_data:
        functions_list = func_data.get("functions", [])
        if isinstance(functions_list, list):
            for f in functions_list:
                if isinstance(f, dict):
                    addr = f.get("address", "")
                    name = f.get("name", "")
                    if addr and name:
                        # Adresleri normalize et: "0x100004a00" formatina cevir
                        if isinstance(addr, str):
                            addr_to_name[addr.lower()] = name
                        elif isinstance(addr, int):
                            addr_to_name[f"0x{addr:x}"] = name

    # CAPA sonuclarindan addr -> name -> capability listesi olustur
    for addr_hex, caps in capa_capabilities.items():
        addr_lower = addr_hex.lower()
        func_name = addr_to_name.get(addr_lower)
        if not func_name:
            # Deneme: "0x" prefix'siz
            try:
                addr_int = int(addr_hex, 16)
                func_name = addr_to_name.get(f"0x{addr_int:x}")
            except (ValueError, TypeError):
                continue
        if func_name:
            cap_names = []
            for c in caps:
                if isinstance(c, dict):
                    cap_names.append(c.get("name", "unknown"))
                elif isinstance(c, str):
                    cap_names.append(c)
            if cap_names:
                name_to_caps[func_name] = cap_names

    if not name_to_caps:
        return 0

    # C dosyalarini tara ve fonksiyon tanimlarinin basina @capability yorumu ekle
    total_injected = 0
    c_files = sorted(decompiled_dir.rglob("*.c"))

    # Fonksiyon tanimi regex: "void FUN_xxx(...)" veya "int func_name(...)"
    # Ghidra decompile output'unda fonksiyonlar genellikle
    # "<return_type> <name>(<params>)" formatinda tanimlanir.
    _func_def_pattern = re.compile(
        r"^(\w[\w\s\*]*?)\s+(\w+)\s*\(",
        re.MULTILINE,
    )

    for c_file in c_files:
        try:
            content = c_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            logger.debug("C dosyasi okunamadi, atlaniyor", exc_info=True)
            continue

        modified = False
        new_lines: list[str] = []
        lines = content.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]
            # Fonksiyon tanimi mi?
            m = _func_def_pattern.match(line)
            if m:
                func_name = m.group(2)
                if func_name in name_to_caps:
                    caps = name_to_caps[func_name]
                    # Onceki satir zaten /** ... */ ise, mevcut blogun sonuna ekle
                    # Yoksa yeni blok olustur
                    cap_lines = [f" * @capability {cap}" for cap in caps]
                    comment_block = "/**\n" + "\n".join(cap_lines) + "\n */"
                    new_lines.append(comment_block)
                    modified = True
                    total_injected += 1

            new_lines.append(line)
            i += 1

        if modified:
            try:
                c_file.write_text("\n".join(new_lines), encoding="utf-8")
            except Exception:
                logger.debug("C dosyasi yazilamadi, atlaniyor", exc_info=True)

    return total_injected
