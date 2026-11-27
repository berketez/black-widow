"""Pipeline stage'leri -- identify, static, dynamic, deobfuscate, reconstruct, report.

Her stage Pipeline'a register edilerek calistirilir. Stage'ler
PipelineContext uzerinden hedef bilgilerine, workspace'e ve
onceki stage sonuclarina erisir.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from karadul.analyzers import get_analyzer
from karadul.core.pipeline import PipelineContext, Stage
from karadul.core.result import StageResult
from karadul.core.target import TargetType, Language
from karadul.pipeline.reconstruction_context import ReconstructionContext

logger = logging.getLogger(__name__)


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


def container_stats(target: Any) -> dict[str, Any]:
    """Tanınan kapsayıcının künyesi (P19 ``container_classifier``); yoksa boş."""
    meta = getattr(target, "metadata", None) or {}
    if not meta.get("container"):
        return {}
    return {
        "container": meta["container"],
        "container_executables": meta.get("container_executables", []),
        # Liste ilk 50 ile sınırlı (core/target.py); toplam ayrıca.
        "container_executables_total": meta.get("container_executables_total"),
    }


def unsupported_target_reason(target: Any) -> str:
    """Analiz hattı olmayan (UNKNOWN) hedefin gerçek nedeni (P-S4 kalem 4/5, BICIM-10).

    Tanınan kapsayıcı (wheel, nupkg, IPA, AAB, XAPK): kapsayıcı türü + P19'un
    ``unsupported_reason``'ı. Tanınmayan dosya: ilk dört bayt (sihirli sayı) ve
    uzantısız JS için yol gösterici not.
    """
    meta = getattr(target, "metadata", None) or {}
    if meta.get("container"):
        why = meta.get("unsupported_reason") or "bu kapsayıcı için analiz hattı yok"
        return f"kapsayıcı tanındı ({meta['container']}) ama doğrudan analiz hattı yok: {why}"
    magic = meta.get("magic")
    return (
        "hedef türü tanınmadı"
        + (f" (sihirli sayı {magic})" if magic else "")
        + "; kayıtlı analizci yok. Uzantısız bir JS dosyasıysa .js uzantısıyla verin."
    )


_UNIVERSAL_SPECIAL_SLICES = (
    ("go_slice", "go", "Go analizcisi (GOPCLNTAB / modül adları)"),
    ("bun_slice", "bun", "Bun gömülü JS çıkarıcısı (__BUN)"),
)


def _note_universal_special_slices(target: Any, result: StageResult) -> None:
    """Evrensel ikilide tanınan ama hattı olmayan dilimleri kayda geçir (BICIM-10).

    P19 ``core/target.py`` dilim başına Go / Bun işaretini ``metadata``'ya yazar,
    tür UNIVERSAL_BINARY kalır (analizcileri şişman dosyayı açmıyor). Eskiden bu bilgi
    hiçbir aşamada görünmüyordu: analist Go adlarının neden kurtarılmadığını bilemezdi.

    P-ÜV6c hüküm 5: hata dizgisi ``<tür>_hatti_error`` istatistiğinde de tutulur. Go için yeni
    okuyucu (``go_metadata_recovery``) aynı koşuda ürün dilimini ``calisti`` ile okursa o adım bu
    dizgiyi (birebir) hata listesinden çıkarır ve bilgi satırı yazar; okuyucu kapalıysa ya da
    okuyamadıysa hata aynen kalır (aşama kısmi).
    """
    meta = getattr(target, "metadata", None) or {}
    for key, kind, hat in _UNIVERSAL_SPECIAL_SLICES:
        if not meta.get(key):
            continue
        reason = (
            f"evrensel ikilide {kind} dilimi tanındı ama {hat} şişman dosyayı açmıyor; "
            "yalnız yerel hat (seçilen dilim) koştu"
        )
        error = f"Desteklenmiyor: {reason}"
        result.stats[f"{kind}_hatti_status"] = "desteklenmiyor"
        result.stats[f"{kind}_hatti_reason"] = reason
        result.stats[f"{kind}_hatti_error"] = error
        result.errors.append(error)


# Not (K-10, 2026-11-19): ``_collect_all_algorithms`` buradan silindi. Çağıranı yoktu
# (AST'de ad / nitelik atfı yalnız testte, dinamik ``getattr`` yok); adımlar
# (semantic_naming, struct_recovery, deep_tracing) kendi kopyalarını kullanıyor.


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


# ---------------------------------------------------------------------------
# Statik asama: YARA ve capa taramalari (P-S1)
# ---------------------------------------------------------------------------
# Durum "her kosulda" yazilir: "tarandi, temiz" ("calisti" + 0) ile
# "taranamadi" ("hata" / "arac_yok" / "desteklenmiyor" / "kapali" + neden)
# ayrilir (IMZA-15). Sozluk P03'un tarayicilariyla ve tarama adimlariyla ayni
# (karadul.pipeline.steps.anti_debug.SCAN_*).

# YARA isabet kaydinda (ARAYUZ-17) isabet basina en cok bu kadar eslesen dizgi
# ve dizgi basina en cok bu kadar bayt yazilir; toplam ``strings_total``'da.
_YARA_HIT_MAX_STRINGS = 8
_YARA_HIT_MAX_DATA = 64

# capa'nin statik asamada cagrildigi hedef turleri (v1.8.6'dan beri ayni liste).
_CAPA_TARGET_TYPES = (
    TargetType.MACHO_BINARY, TargetType.UNIVERSAL_BINARY,
    TargetType.ELF_BINARY, TargetType.PE_BINARY, TargetType.GO_BINARY,
    TargetType.BUN_BINARY,
)


def _json_safe(value: Any) -> Any:
    """YARA meta degerleri JSON'a yazilabilir olsun (bytes -> onaltilik)."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return str(value)


def _yara_hit_record(match: Any) -> dict[str, Any]:
    """Tek YARA isabetinin yapilandirilmis kaydi (ARAYUZ-17).

    Alanlar: ``rule``, ``tags`` (liste), ``meta`` (kuralin meta'si; P03'te
    ``condition`` = hukmun okunur kosulu), ``namespace``, ``strings`` (en cok
    ``_YARA_HIT_MAX_STRINGS`` eslesme: ``offset``, ``identifier``, ``length``,
    ``data_hex`` (en cok ``_YARA_HIT_MAX_DATA`` bayt), ``data_text`` (yalniz
    yazdirilabilir ASCII ise, degilse None)), ``strings_total``.
    """
    raw = list(getattr(match, "strings", None) or [])
    shown: list[dict[str, Any]] = []
    for off, ident, data in raw[:_YARA_HIT_MAX_STRINGS]:
        data = bytes(data or b"")
        head = data[:_YARA_HIT_MAX_DATA]
        printable = bool(head) and all(0x20 <= b < 0x7F for b in head)
        shown.append({
            "offset": int(off),
            "identifier": str(ident),
            "length": len(data),
            "data_hex": head.hex(),
            "data_text": head.decode("ascii") if printable else None,
        })
    meta = getattr(match, "meta", None) or {}
    return {
        "rule": str(match.rule),
        "tags": [str(t) for t in (getattr(match, "tags", None) or [])],
        "meta": {str(k): _json_safe(v) for k, v in dict(meta).items()},
        "namespace": str(getattr(match, "namespace", "") or ""),
        "strings": shown,
        "strings_total": len(raw),
    }


def _run_yara_scan(target_path: Path, stats: dict[str, Any]) -> None:
    """Yerlesik YARA kurallariyla tara; durum ve isabetleri ``stats``'a yaz.

    Her kosulda: ``yara_status``, ``yara_status_reason``. Tarama calistiysa
    ayrica ``yara_backend``, ``yara_rules_loaded``, ``yara_scan_time_ms``,
    yedege dusulduyse ``yara_fallback_reason``.

    ``yara_matches`` (int) ve ``yara_hits`` (yapilandirilmis liste, ARAYUZ-17)
    yalniz ``calisti``da sayidir; ``hata`` / ``arac_yok``da ``None``
    ("0 eslesme" yazilmaz). Gecis icin eski duz liste ``detected_tech``
    (``"<kural> (<etiketler>)"``) da yazilir: okuyanlar ``sarif_report.py``,
    ``scripts/measurement/masum_kapi.py`` (``cikti_yara``),
    ``scripts/measurement/saglamlik_denetle.py``. Yeni okuyucu ``yara_hits``'i
    kullanir; ikisi birlikte okunursa ayni isabet iki kez sayilir.
    """
    from karadul.pipeline.steps.anti_debug import SCAN_ERROR, SCAN_NO_TOOL, SCAN_RAN

    stats["yara_matches"] = None
    stats["yara_hits"] = None
    try:
        from karadul.analyzers.yara_scanner import YaraScanner
    except ImportError as exc:
        stats["yara_status"] = SCAN_NO_TOOL
        stats["yara_status_reason"] = f"yara_scanner yuklenemedi: {exc}"
        logger.warning("YaraScanner bulunamadi: %s", exc)
        return
    # Tarama ve sonucun okunmasi tek blokta: beklenmeyen bicimde bir sonuc da
    # (eksik alan) "hata" olur, asamayi dusurmez ve yarim sayac birakmaz.
    try:
        scanner = YaraScanner()
        scanner.load_builtin_rules()
        yara_result = scanner.scan_file(target_path)
        out: dict[str, Any] = {
            "yara_status": yara_result.status,
            "yara_status_reason": yara_result.status_reason,
            "yara_backend": yara_result.backend,
            "yara_rules_loaded": yara_result.total_rules,
            "yara_scan_time_ms": yara_result.scan_time_ms,
        }
        if yara_result.fallback_reason:
            out["yara_fallback_reason"] = yara_result.fallback_reason
        tech: list[str] = []
        if yara_result.status == SCAN_RAN:
            out["yara_matches"] = len(yara_result.matches)
            out["yara_hits"] = [_yara_hit_record(m) for m in yara_result.matches]
            for m in yara_result.matches:
                tags_str = ",".join(m.tags) if m.tags else "unknown"
                tech.append(f"{m.rule} ({tags_str})")
    except Exception as exc:
        stats["yara_status"] = SCAN_ERROR
        stats["yara_status_reason"] = f"{type(exc).__name__}: {exc}"
        logger.warning("YARA tarama hatasi (taranamadi): %s", exc)
        return

    stats.update(out)
    if tech:
        stats.setdefault("detected_tech", []).extend(tech)
    logger.info(
        "YARA: %s, %s kural eslesti (%s backend, %.1fms)%s",
        yara_result.status, stats["yara_matches"], yara_result.backend,
        yara_result.scan_time_ms,
        f" -- {yara_result.status_reason}" if yara_result.status_reason else "",
    )


def _run_capa_scan(context: PipelineContext, target: Any, stats: dict[str, Any]) -> None:
    """capa yetenek taramasi; durum ``stats``'a, kayit ``static/capa_scan.json``'a.

    Her kosulda ``capa_status`` + ``capa_status_reason`` yazilir: tarayicinin
    dondurdugu (``calisti`` / ``arac_yok`` / ``hata`` / ``desteklenmiyor``) ya da
    asama duzeyinde ``kapali`` (``enable_capa=False``) ve ``desteklenmiyor``
    (asama capa'yi bu hedef turunde cagirmiyor).

    K-1: tarayicinin tam sonucu her zaman ``static/capa_scan.json``'a (rapor
    icin) yazilir. Ad birlestiricinin ve ``capa_annotation`` adiminin girdisi
    ``static/capa_capabilities.json`` ise YALNIZ ``enable_capa_code_feed``
    acikken yazilir (``capa_annotation.capa_code_feed_enabled``; ontanimli
    kapali): olculene kadar capa koda ad ya da yorum olarak girmez.
    """
    from karadul.pipeline.steps.anti_debug import (
        SCAN_DISABLED, SCAN_ERROR, SCAN_NO_TOOL, SCAN_RAN, SCAN_UNSUPPORTED,
    )
    from karadul.pipeline.steps.capa_annotation import (
        CAPA_CODE_FEED_FLAG, capa_code_feed_enabled,
    )

    br = context.config.binary_reconstruction
    if target.target_type not in _CAPA_TARGET_TYPES:
        stats["capa_status"] = SCAN_UNSUPPORTED
        stats["capa_status_reason"] = (
            f"asama capa'yi bu hedef turunde cagirmiyor: {target.target_type.value}"
        )
        return
    if not br.enable_capa:
        stats["capa_status"] = SCAN_DISABLED
        stats["capa_status_reason"] = "enable_capa=False"
        return

    context.report_progress("CAPA capability detection...", 0.85)
    try:
        from karadul.analyzers.capa_scanner import CAPAScanner
    except ImportError as exc:
        stats["capa_status"] = SCAN_NO_TOOL
        stats["capa_status_reason"] = f"capa_scanner yuklenemedi: {exc}"
        logger.debug("capa_scanner yuklenemedi: %s", exc)
        return
    try:
        capa_scanner = CAPAScanner(
            rules_path=br.capa_rules_path or None,
            timeout=br.capa_timeout,
        )
        # P03: scan() arac yokken de durum dondurur (arac_yok + neden).
        capa_result = capa_scanner.scan(target.path)
        # Sonucun okunmasi da bu blokta: beklenmeyen bicim "hata" olur.
        record = capa_result.to_dict()
    except Exception as exc:
        stats["capa_status"] = SCAN_ERROR
        stats["capa_status_reason"] = f"{type(exc).__name__}: {exc}"
        logger.warning("CAPA scan hatasi (taranamadi): %s", exc)
        return

    feed = capa_code_feed_enabled(context.config)
    stats["capa_status"] = capa_result.status
    stats["capa_status_reason"] = capa_result.status_reason
    stats["capa_backend"] = capa_result.backend
    stats["capa_code_feed"] = feed
    record["code_feed"] = {
        "enabled": feed,
        "flag": f"binary_reconstruction.{CAPA_CODE_FEED_FLAG}",
        "note": ("capa sonuclari koda ad / yorum olarak girer" if feed else
                 "K-1: capa sonuclari yalniz raporda; koda ad / yorum olarak girmez"),
    }
    try:
        context.workspace.save_json("static", "capa_scan", record)
    except Exception as exc:  # pragma: no cover - defansif
        logger.warning("capa_scan.json yazilamadi: %s", exc)
    if capa_result.status != SCAN_RAN:
        logger.info("CAPA %s: %s", capa_result.status, capa_result.status_reason)
        return
    stats["capa_rules_matched"] = capa_result.total_rules_matched
    stats["capa_functions_matched"] = capa_result.total_functions_matched
    stats["capa_file_capabilities"] = len(capa_result.file_capabilities)
    stats["capa_duration"] = round(capa_result.duration_seconds, 1)
    if feed:
        # Ad birlestirici (run_capa_merge) ve capa_annotation bu dosyayi okur.
        context.workspace.save_json(
            "static", "capa_capabilities", capa_result.to_dict(),
        )
    logger.info(
        "CAPA: %d kural eslesti, %d fonksiyonda capability (%.1fs, format=%s); "
        "koda besleme %s",
        capa_result.total_rules_matched, capa_result.total_functions_matched,
        capa_result.duration_seconds, capa_result.format_,
        "acik" if feed else "kapali (K-1)",
    )


def _finalize_binary_outcome(
    stage_result: StageResult, naming_result: Any, config: Any,
) -> None:
    """Binary reconstruct sonucunun basarisini Faz 1-3 birlesmis haliyle yeniden hesapla.

    P-S1 / BORU-05: eskiden ``success = len(artifacts) > 0`` idi (anti_debug
    JSON'u her kosulda yapit oldugu icin fiilen hep True). Olcut finalize
    adimindaki ``reconstruct_outcome``'tir (tek kaynak): proje kuruldu VE C
    adlandirma hatasiz; Faz 1/2 hatalari ``partial`` nedenlerine katilir.
    """
    from karadul.pipeline.steps.finalize import c_naming_enabled, reconstruct_outcome

    outcome = reconstruct_outcome(
        artifacts=stage_result.artifacts,
        errors=stage_result.errors,
        naming_result=naming_result,
        naming_enabled=c_naming_enabled(config),
    )
    stage_result.success = outcome["success"]
    stage_result.stats.update(outcome["stats"])
    if not stage_result.success:
        logger.warning(
            "reconstruct basarisiz: %s",
            "; ".join(outcome["stats"]["reconstruct_failure_reasons"]),
        )


class StaticAnalysisStage(Stage):
    """Statik analiz stage'i.

    Hedef tipine uygun analyzer'i bulur ve analyze_static() cagistirir.
    """

    name = "static"
    requires: tuple[str, ...] = ("identify",)

    def execute(self, context: PipelineContext) -> StageResult:
        """Analyzer ile statik analiz calistir."""
        start = time.monotonic()

        target = context.target

        # APP_BUNDLE ise ozel akis: tum bilesenleri paralel analiz et
        if target.target_type == TargetType.APP_BUNDLE:
            return self._execute_app_bundle(context, start)

        # P-S4 kalem 5 (P-S1 notu, BICIM-10): tanınan kapsayıcıda ya da tanınmayan
        # türde "Analyzer bulunamadi: No analyzer registered for TargetType.UNKNOWN"
        # yanıltıcıydı. Durum açık: desteklenmiyor + gerçek neden. Aşama yine
        # başarısız sayılır (analiz yapılmadı; 'tam' çıkış kodu sahte başarı olurdu).
        if target.target_type == TargetType.UNKNOWN:
            reason = unsupported_target_reason(target)
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                stats={"static_status": "desteklenmiyor", "status_reason": reason,
                       **container_stats(target)},
                errors=[f"Desteklenmiyor: {reason}"],
            )

        # Uygun analyzer'i bul
        try:
            analyzer_cls = get_analyzer(target.target_type)
        except ValueError as exc:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                stats={"static_status": "desteklenmiyor",
                       "status_reason": f"{target.target_type.value}: kayıtlı analizci yok"},
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

        # BICIM-10 (P-S4): evrensel dosyada Go / Bun dilimi tanındı (P19 işareti) ama
        # bu hatların analizcileri şişman dosyayı açmıyor; yerel hat seçilen dilimde
        # koştu. Sessiz kalmasın: hat 'desteklenmiyor' + neden, aşama kısmi.
        if target.target_type == TargetType.UNIVERSAL_BINARY:
            _note_universal_special_slices(target, result)

        # YARA taramasi -- yerlesik kurallar (P03 + P-S1: durum her kosulda,
        # isabetler yapilandirilmis ``yara_hits`` olarak da yazilir).
        context.report_progress("YARA pattern scanning...", 0.8)
        _run_yara_scan(target.path, result.stats)

        # v1.8.6: CAPA capability detection -- binary hedefler icin.
        # P-S1: durum her kosulda; koda besleme K-1 bayragi arkasinda (kapali).
        _run_capa_scan(context, target, result.stats)

        # FLIRT (FLIRT yükleme bug'ı, 2026-09-25): bu aşama artık FLIRT imzası
        # YÜKLEMEZ ve SAYMAZ. İmzalar yalnız reconstruct'taki byte_pattern
        # adımında yüklenir, eşleştirilir ve sayılır (tek kaynak):
        #   reconstruct.stats.flirt_signatures_loaded / flirt_signature_sources /
        #   flirt_signatures_matchable / flirt_functions_scanned / flirt_functions_named
        # Eski blok burada signatures_homebrew.json + sigs/*.json yüklüyordu:
        # 2,46M İSİM imzası, hiçbirinde bayt deseni yok, hiçbir eşleştirmeye
        # girmiyordu (çıktısı static/flirt_signatures.json'u okuyan kod yoktu).
        # Ölçüm (coreutils cat, imzalar erişilebilirken): +10,9 sn, RSS
        # 0,86 GB -> 3,9 GB. Sayaç da eşleşmeye giren imzaları değil bu
        # listeyi raporluyordu; --output-dir ile kök kaydığında ise 0.

        # Stage name'i zorla ayarla (analyzer farkli isim vermis olabilir)
        result.stage_name = self.name
        return result

    def _execute_app_bundle(
        self, context: PipelineContext, start: float,
    ) -> StageResult:
        """APP_BUNDLE icin ozel statik analiz akisi.

        AppBundleAnalyzer tüm bileşenleri (binary, JAR, framework, Electron)
        sırayla, her birini kendi alt-workspace'inde analiz eder. En çok
        fonksiyonu olan başarılı bileşeni 'ana bileşen' olarak işaretler ve
        çıktılarını üst workspace'e taşır (reconstruct, raporlar ve arayüz üst
        workspace'in static/ dizinini okur).
        """
        from karadul.analyzers.app_bundle import (
            AppBundleAnalyzer,
            promote_component_outputs,
        )

        target = context.target
        stats: dict = {}
        errors: list[str] = []

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
        # CLI sonuç tablosu, JSON/MD/HTML raporları ve batch özeti statik
        # sayacı "functions_found"/"strings_found" anahtarından okur; bundle
        # dalında bu anahtarlar yoktu -> "Functions recovered 0".
        stats["functions_found"] = bundle_result.total_functions
        stats["strings_found"] = bundle_result.total_strings
        stats["target_type"] = "app_bundle"

        # Ana bileşen: önce tür (uygulama kodu > JAR > ana ikili > çerçeve), sonra
        # fonksiyon sayısı (BICIM-09); gerekçe ve bileşen listesi kayıtta.
        main_comp = bundle_result.main_component
        stats["main_selection_reason"] = bundle_result.main_selection_reason
        stats["bundle_component_list"] = [
            {"name": r.name, "type": r.component_type, "success": r.success,
             "functions": r.functions_found}
            for r in bundle_result.component_results
        ]
        if main_comp is not None:
            stats["main_component_type"] = main_comp.component_type
            context.metadata["main_component"] = main_comp.path
            context.metadata["main_component_type"] = main_comp.component_type
            context.metadata["main_component_name"] = main_comp.name
            context.metadata["main_component_workspace"] = main_comp.workspace
            stats["main_component"] = main_comp.name
            stats["main_component_functions"] = main_comp.functions_found
            stats["main_component_workspace"] = main_comp.workspace
            if main_comp.workspace:
                try:
                    promoted = promote_component_outputs(
                        context.workspace, main_comp.workspace,
                    )
                    stats["main_component_promoted"] = len(promoted)
                except Exception as exc:
                    logger.warning(
                        "Ana bileşen çıktıları üst workspace'e taşınamadı: %s", exc,
                    )
                    errors.append(f"Ana bileşen çıktıları taşınamadı: {exc}")

        errors.extend(
            f"{r.name}: {r.error}"
            for r in bundle_result.component_results
            if not r.success and r.error
        )

        return StageResult(
            stage_name=self.name,
            success=bundle_result.success,
            duration_seconds=time.monotonic() - start,
            artifacts={},
            stats=stats,
            errors=errors,
        )


class DynamicAnalysisStage(Stage):
    """Dinamik analiz stage'i -- Frida ile runtime izleme.

    Hedef tipine gore uygun hook script'i secer (nodejs, objc, generic),
    process'i spawn veya attach eder, belirli sure veri toplar,
    FunctionTracer ile analiz eder ve sonuclari workspace/dynamic/ altina kaydeder.

    Frida kurulu degilse veya SIP kisitlamasi varsa graceful skip yapar.
    """

    name = "dynamic"
    requires: tuple[str, ...] = ("identify",)  # static'ten bagimsiz calisabilir

    def _skipped(self, start: float, reason: str) -> StageResult:
        """Dinamik analiz ATLANDI sonucu (hata DEGIL).

        Frida yoksa ya da hedef bu ortamda spawn edilemiyorsa (yabanci mimari /
        cross-arch, ornegin macOS'ta Linux ELF) dinamik analiz *uygulanamaz* --
        bu bir basarisizlik degildir. skipped=True doner; PipelineResult bunu
        FAILED saymaz (bkz result.add_stage_result / get_failed_stages).
        """
        return StageResult(
            stage_name=self.name,
            success=False,
            skipped=True,
            duration_seconds=time.monotonic() - start,
            stats={"skip_reason": reason},
        )

    def execute(self, context: PipelineContext) -> StageResult:
        """Frida ile dinamik analiz calistir."""
        start = time.monotonic()
        errors: list[str] = []
        artifacts: dict[str, Path] = {}
        stats: dict = {}

        # Hedef program yalnız açık istekle çalıştırılır (CLI --dynamic). Bilinmeyen
        # ya da zararlı bir ikili analiz edilirken varsayılan olarak çalışmamalı.
        # GHIDRA-07: yalnız gerçek ``True`` kapıyı açar ("false" dizgisi gibi
        # doğruluk değeri taşıyan her şey kapalı sayılır).
        if context.config.security.allow_target_execution is not True:
            return self._skipped(
                start, "hedef programı çalıştırmak için açık izin yok (--dynamic)",
            )

        # Bilinmeyen tipte hedef hiçbir koşulda çalıştırılmaz (GHIDRA-07).
        spawn_plan = self._spawn_plan(context.target, context.config)
        if spawn_plan is None:
            return self._skipped(
                start,
                "hedef tipi (%s) için tanımlı çalıştırma yolu yok; bilinmeyen tip "
                "çalıştırılmaz" % getattr(context.target.target_type, "value",
                                          context.target.target_type),
            )

        # Frida import kontrolu
        try:
            from karadul.frida.session import FridaSession, FridaNotAvailableError, FridaAttachError
            from karadul.frida.collectors.function_tracer import FunctionTracer
        except ImportError as exc:
            logger.debug("Frida modulleri yuklenemedi, dinamik analiz atlaniyor", exc_info=True)
            return self._skipped(start, f"Frida modulleri yuklenemedi: {exc}")

        # FridaSession olustur
        try:
            session = FridaSession(context.config)
        except FridaNotAvailableError as exc:
            logger.debug("Frida kurulu degil, dinamik analiz atlaniyor", exc_info=True)
            return self._skipped(start, str(exc))

        target = context.target
        hooks_dir = Path(__file__).parent / "frida" / "hooks"

        # Hedef tipine gore hook script sec
        hook_script = self._select_hook_script(target, hooks_dir)
        if hook_script and not hook_script.exists():
            errors.append(f"Hook script bulunamadi: {hook_script}")
            hook_script = None

        skipped = False
        success = False

        try:
            # GHIDRA-11 (2026-11-18): sıra spawn (askıda) -> kanca yükle ->
            # resume -> bekle -> kill. Eskiden süreç kancasız sürdürülüyor ve
            # analiz bitince hiç öldürülmüyordu.
            program, program_args, spawn_method = spawn_plan
            pid = session.spawn(program, args=program_args)  # askıda başlar
            stats["spawn_method"] = spawn_method
            stats["pid"] = pid

            # Hook script yukle -- süreç hâlâ askıda
            loaded_hook: str | None = None
            if hook_script:
                session.load_script(hook_script)
                loaded_hook = hook_script.name
            else:
                # Generic hooks her zaman yukle
                generic_hook = hooks_dir / "generic_hooks.js"
                if generic_hook.exists():
                    session.load_script(generic_hook)
                    loaded_hook = "generic_hooks.js"
            if loaded_hook is None:
                # Kancasız çalıştırmanın gözlem değeri yok, yalnız riski var.
                raise RuntimeError("kanca betiği yüklenemedi; hedef sürdürülmedi")
            stats["hook_script"] = loaded_hook

            # Kancalar yerinde: süreci şimdi sürdür.
            session.resume()

            # Veri toplama suresi (gerçek süre yazılır; süreç erken biterse kısa)
            collect_timeout = float(context.config.timeouts.frida_attach)
            elapsed = session.wait(timeout=collect_timeout)
            stats["collect_timeout"] = collect_timeout
            stats["collect_duration"] = round(float(elapsed), 3)
            if session.detach_reason is not None:
                stats["frida_detach_reason"] = session.detach_reason

            # Toplama bitti: hedef süreç öldürülür (gözetimsiz çalışmaya devam etmez).
            # True: öldürüldü ya da zaten bitmişti (canlı spawn süreci kalmadı).
            stats["target_terminated"] = session.kill()

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

            # Sonuclari workspace'e kaydet (save_json "dynamic" dizinini kendisi kurar)

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
            # Spawn/attach basarisiz -- en yaygin sebep hedefin bu ortamda
            # calistirilamamasi (yabanci mimari / cross-arch: macOS'ta Linux
            # ELF, ya da SIP). Bu bir ANALIZ HATASI degil, dinamik analizin
            # UYGULANAMAMASIdir -> ATLA (skipped), pipeline'i FAILED yapma.
            logger.debug("Frida spawn/attach basarisiz, dinamik analiz atlaniyor: %s", exc, exc_info=True)
            stats["skip_reason"] = f"Frida attach/spawn yapilamadi: {exc}"
            success = False
            skipped = True

        except Exception as exc:
            errors.append(f"Dinamik analiz hatasi: {type(exc).__name__}: {exc}")
            logger.exception("DynamicAnalysisStage exception")
            success = False

        finally:
            # Session'i her zaman kapat; detach öldürülmemiş spawn sürecini de
            # öldürür (istisna yolu dahil). Öldürülemezse bu sessiz geçilmez.
            try:
                session.detach()
            except Exception as exc:
                logger.error("Frida oturumu kapatılamadı / hedef süreç öldürülemedi: %s", exc)
                errors.append(
                    f"Frida oturumu kapatılamadı / hedef süreç öldürülemedi: {exc}"
                )
                stats["target_terminated"] = False
                success = False

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
            skipped=skipped,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    @staticmethod
    def _spawn_plan(target, config) -> tuple[str, list[str], str] | None:
        """Hedef tipine göre (program, argümanlar, yöntem); bilinmeyen tipte None.

        GHIDRA-07: eskiden ``TargetType.UNKNOWN`` da ``generic_spawn`` ile
        doğrudan başlatılıyordu. Artık tanınmayan dosya hiçbir koşulda
        çalıştırılmaz; dinamik aşama atlanır. Tanınan öbür tipler (BUN, Delphi,
        PyInstaller paketi vb.) eskisi gibi ``generic_spawn`` yolundadır.
        """
        target_path = str(target.path)
        if target.target_type == TargetType.JS_BUNDLE:
            # JS bundle: node ile spawn et
            return str(config.tools.node), [target_path], "node_spawn"
        if target.target_type in (
            TargetType.MACHO_BINARY, TargetType.UNIVERSAL_BINARY,
            TargetType.GO_BINARY,
            TargetType.ELF_BINARY, TargetType.PE_BINARY,
        ):
            # Native binary: dogrudan spawn et
            return target_path, [], "direct_spawn"
        if target.target_type == TargetType.ELECTRON_APP:
            # Electron: ana binary'yi spawn et
            main_binary = (target.metadata or {}).get("main_binary")
            return str(main_binary or target_path), [], "electron_spawn"
        if target.target_type == TargetType.UNKNOWN:
            return None
        # Tanınan öbür tipler: dogrudan spawn dene (eski davranış)
        return target_path, [], "generic_spawn"

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
    """Deobfuscation stage'i -- hedef türüne göre yönlendirilir.

    - GO_BINARY: Go deobfuscation + binary deobfuscation (hibrit).
    - Native (MACHO/UNIVERSAL/ELF/PE/BUN/DELPHI): BinaryDeobfuscator (Ghidra çıktısı temizliği).
    - JS ailesi (JS_BUNDLE, ELECTRON_APP): DeepDeobfuscationPipeline -- 9 phase Babel
      transform + akilli modul cikarma. (Eski ``use_deep=False`` yolu -- Analyzer'in
      deobfuscate()'i -- hiçbir yerde kurulmuyordu; 2026-11-18'de silindi, K-3 A1.)
    - JAVA_JAR, ANDROID_APK: kayıtlı analizcinin deobfuscate()'i (ProGuard/R8).
    - Geri kalan her şey (DOTNET_ASSEMBLY, PYTHON_PACKED, APP_BUNDLE, UNKNOWN ve
      tablolarda olmayan her yeni tür): ATLANDI (skipped=True + skip_reason).

    Not: ``requires`` listesi kasitli olarak ["identify"] yapildi (eskiden ["static"]).
    Static analiz basarisiz olsa bile (orn. Babel parse hatasi) deobfuscation
    devam edebilmelidir -- deobfuscation kendi icerisinde beautify + Babel/Acorn
    fallback kullaniyor.
    """

    name = "deobfuscate"
    requires: tuple[str, ...] = ("identify",)

    # Yönlendirme bug'ı (2026-09-25): eskiden native olmayan HER tür, türüne
    # bakılmadan JS derin hattına (beautify.mjs, Babel, webpack unpack) düşüyordu.
    # İkili dosyada beautify'ın "başarılı" adımı (ya da hata sonrası kopyası) aşamayı
    # sahte başarıya çeviriyordu. Ölçüm (CLI, --stage deobfuscate): PyInstaller 7,8 MB
    # -> deobfuscated/ altında 29,85 MB çöp; .NET 251 KB -> 58,97 MB; JAR/APK/.pyc da
    # aynı desen, hepsi success=True. ReconstructionStage'deki aynı tuzak 61f6bba'da
    # (JVM/.NET/APK/Python) düzeltilmişti; bu tablolar onun deobfuscation karşılığı.

    # JS derin hattı yalnız JS kaynağı üstünde anlamlı.
    _JS_FAMILY: frozenset[TargetType] = frozenset({
        TargetType.JS_BUNDLE,
        TargetType.ELECTRON_APP,
    })

    # Kendi analizcisinde formata özgü deobfuscation mantığı olan türler.
    # JavaBinaryAnalyzer.deobfuscate: static'teki ProGuard/R8 tespitini okur,
    # mapping.txt varsa yükler.
    _ANALYZER_DEOB_TYPES: frozenset[TargetType] = frozenset({
        TargetType.JAVA_JAR,
        TargetType.ANDROID_APK,
    })

    # Anlamlı deobfuscation'ı olmayan türler -> ATLANDI (ne sahte başarı ne hata).
    # Bir analizcinin deobfuscate()'i gerçek iş yapar hâle gelirse türü buradan
    # _ANALYZER_DEOB_TYPES'a taşı.
    #   DOTNET_ASSEMBLY: DotNetBinaryAnalyzer.deobfuscate boş sonuç döndüren bir taslak.
    #   PYTHON_PACKED:   PythonBinaryAnalyzer.deobfuscate yalnız static JSON'unu
    #                    deobfuscated/'a kopyalıyor, okuyan yok; asıl kurtarma
    #                    (CArchive/PYZ çıkarma + decompile) reconstruct'ta.
    #   APP_BUNDLE:      AppBundleAnalyzer'da deobfuscate yok; JS derin hattı .app
    #                    dizinini dosya sanıp IsADirectoryError veriyordu.
    #   UNKNOWN:         kayıtlı analizci yok. Uzantısız JS de buraya düşer; bu
    #                    türde gerçekte görülen hedefler .py kaynaklarıydı (JS derin
    #                    hattı Python'u "beautify" edip başarı diyordu).
    _SKIP_REASONS: dict[TargetType, str] = {
        TargetType.DOTNET_ASSEMBLY: (
            ".NET assembly için deobfuscation uygulanmıyor (ConfuserEx vb. "
            "çözücü yok); JS hattı bu türe uygulanmaz."
        ),
        TargetType.PYTHON_PACKED: (
            "Python paketi için ayrı bir deobfuscation adımı yok; .pyc çıkarma "
            "ve decompile reconstruct aşamasında yapılır."
        ),
        TargetType.APP_BUNDLE: (
            ".app bundle için bileşen bazlı deobfuscation tanımlı değil; "
            "bileşenler static aşamasında ayrı ayrı analiz edilir."
        ),
        TargetType.UNKNOWN: (
            "Hedef türü tanınmadı; deobfuscation uygulanmadı. Uzantısız bir "
            "JS dosyasıysa .js uzantısıyla verin."
        ),
    }

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

        # JS ailesi: derin JS hattı yalnız burada çalışır.
        if target.target_type in self._JS_FAMILY:
            return self._execute_deep(context, start)

        # BICIM-09 (P-S4): .app'in ana bileşeni Electron JS ya da JAR ise o
        # bileşenin hattı koşar (eskiden APP_BUNDLE hep atlanıyordu; Electron
        # reconstruct'ı "Deobfuscate edilmis dosya bulunamadi" ile düşüyordu).
        if target.target_type == TargetType.APP_BUNDLE:
            return self._execute_app_bundle(context, start)

        # JVM/Dalvik: formatın kendi analizcisi.
        if target.target_type in self._ANALYZER_DEOB_TYPES:
            return self._execute_analyzer_deobfuscate(context, start)

        # P-S4 kalem 5: tanınan kapsayıcıda "Hedef türü tanınmadı" yanlıştı.
        if target.target_type == TargetType.UNKNOWN:
            return self._skipped(start, unsupported_target_reason(target))

        # Geri kalan her şey ATLANDI -- asla JS hattına düşmez (yeni türler dahil).
        reason = self._SKIP_REASONS.get(
            target.target_type,
            f"{target.target_type.value}: bu hedef türü için deobfuscation yolu "
            "tanımlı değil.",
        )
        return self._skipped(start, reason)

    def _execute_app_bundle(self, context: PipelineContext, start: float) -> StageResult:
        """APP_BUNDLE: ana bileşenin türüne göre deobfuscation (BICIM-09).

        Static aşaması ana bileşeni seçip ``context.metadata``'ya yazar ve çıktılarını
        (``raw/asar_extracted`` dahil) üst workspace'e taşır. Electron / JS bileşeni
        derin JS hattına, JAR kendi analizcisine gider; yerel ana bileşende
        deobfuscation tanımlı değil (eskisi gibi 'atlandı').
        """
        main_type = context.metadata.get("main_component_type")
        main_path = context.metadata.get("main_component")
        if main_type not in ("electron_app", "js_bundle", "java_jar") or not main_path:
            return self._skipped(start, self._SKIP_REASONS[TargetType.APP_BUNDLE] + (
                f" Ana bileşen: {main_type or 'yok'}."
            ))
        from karadul.analyzers.app_bundle import build_component_target, component_context

        comp = {"path": main_path, "type": main_type,
                "name": context.metadata.get("main_component_name", "")}
        comp_ctx = component_context(
            context, build_component_target(comp, context.target.name),
        )
        if main_type == "java_jar":
            res = self._execute_analyzer_deobfuscate(comp_ctx, start)
        else:
            res = self._execute_deep(comp_ctx, start)
        res.stats["bundle_main_component"] = comp["name"]
        res.stats["bundle_main_component_type"] = main_type
        return res

    def _skipped(self, start: float, reason: str) -> StageResult:
        """Deobfuscation ATLANDI sonucu (hata DEĞİL).

        DynamicAnalysisStage._skipped ile aynı sözleşme: success=False +
        skipped=True; PipelineResult bunu FAILED saymaz (get_skipped_stages'te
        listelenir), gerekçe stats["skip_reason"]'da.
        """
        logger.info("Deobfuscation atlandı: %s", reason)
        return StageResult(
            stage_name=self.name,
            success=False,
            skipped=True,
            duration_seconds=time.monotonic() - start,
            stats={"skip_reason": reason},
        )

    def _execute_analyzer_deobfuscate(
        self, context: PipelineContext, start: float,
    ) -> StageResult:
        """Kayıtlı analizcinin kendi deobfuscate()'i (JAR/APK -> JavaBinaryAnalyzer).

        ReconstructionStage._execute_analyzer_reconstruct'ın deobfuscation
        karşılığı: analizci patlarsa ya da None dönerse aşama başarısız olur,
        pipeline ölmez.
        """
        target_kind = context.target.target_type.value
        try:
            analyzer_cls = get_analyzer(context.target.target_type)
            analyzer = analyzer_cls(context.config)
            result = analyzer.deobfuscate(context.target, context.workspace)
        except Exception as exc:
            logger.exception("%s deobfuscation hatası: %s", target_kind, exc)
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
                errors=[f"{target_kind} deobfuscation sonuç döndürmedi"],
            )
        result.stage_name = self.name
        return result

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

    def _resolve_deob_input(self, context: PipelineContext) -> Path | None:
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

            # BICIM-02 (P-S4): ASAR arşivi / uygulama dizini JS değildir. Eskiden
            # burada hedefin kendisi (ikili .asar) derin hatta veriliyor, beautify
            # çöpü "01_beautified.js" olup yeniden kurmaya giriyordu.
            if target.path.suffix.lower() not in (".js", ".mjs", ".cjs"):
                logger.warning(
                    "Electron deob: çıkarılmış JS bulunamadı; %s JS değil, "
                    "deobfuscation uygulanmaz", target.path.name,
                )
                return None
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
        if input_file is None:
            # BICIM-02 (P-S4): Electron hedefinde deobfuscate edilecek JS yok
            # (ASAR'da .js yok ya da çıkarma başarısız): ikili arşiv JS hattına girmez.
            return self._skipped(
                start,
                f"{context.target.path.name}: çıkarılmış JS dosyası yok (ASAR / uygulama "
                "dizininde .js bulunamadı ya da çıkarılamadı); deobfuscation uygulanmadı.",
            )

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
    requires: tuple[str, ...] = ("identify",)  # v1.9.1: deobfuscate -> identify (native binary'de deobf gereksiz)

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

        # Native-olmayan / analizor-reconstruct formatlar (JVM/.NET/Dalvik/Python-packed):
        # Ghidra veya JS deobfuscation yoluna dusmemeli. Eskiden hepsi _execute_js'e dusup
        # JS iskeleti + "0 fonksiyon" uretiyordu (kapsam bug'i). Her birinin kayitli
        # analizoru kendi reconstruct'ini calistirir:
        #   JAVA_JAR + ANDROID_APK -> JavaBinaryAnalyzer (class/metot; jadx varsa kaynak)
        #   DOTNET_ASSEMBLY        -> DotNetBinaryAnalyzer (CIL metot; ILSpy varsa kaynak)
        #   PYTHON_PACKED          -> PythonBinaryAnalyzer (PyInstaller CArchive -> .pyc)
        if target.target_type in (
            TargetType.JAVA_JAR,
            TargetType.ANDROID_APK,
            TargetType.DOTNET_ASSEMBLY,
            TargetType.PYTHON_PACKED,
        ):
            return self._execute_analyzer_reconstruct(context, start)

        # P19 / BICIM-10: tanınan ama analiz hattı olmayan kapsayıcı (wheel, IPA,
        # nupkg, AAB, XAPK; target.metadata["container"]) JS hattına düşüp
        # "Deobfuscate edilmis dosya bulunamadi" demesin: açık "atlandı".
        # P-S4 (BICIM-10): tanınmayan tür de (kapsayıcı değilse) JS hattına düşüp
        # "Deobfuscate edilmis dosya bulunamadi" demesin; uzantısız JS UNKNOWN'dır
        # ve deobfuscation zaten atlanır (JS hattında işlenecek kaynak yok).
        if target.target_type == TargetType.UNKNOWN:
            return StageResult(
                stage_name=self.name, success=False, skipped=True,
                duration_seconds=time.monotonic() - start,
                stats={"skip_reason": unsupported_target_reason(target),
                       **container_stats(target)},
            )

        return self._execute_js(context, start)

    def _execute_app_bundle(self, context: PipelineContext, start: float) -> StageResult:
        """APP_BUNDLE reconstruction — ana bileşen için tam reconstruction.

        StaticAnalysisStage'in bundle_analysis sonucunu okur; ana bileşeni
        (static stage'in seçtiği = en çok fonksiyonu olan başarılı bileşen)
        bileşen tipine göre reconstruct eder.

        Adımlar ana bileşene DARALTILMIŞ bir context ile koşar: pc.target.path
        paketin .app dizini değil bileşenin gerçek binary'sidir; target_type,
        name ve file_hash da bileşenin. Eskiden bundle context'i aynen
        geçirildiği için binary_prep/byte_pattern/anti_debug/packer_fingerprint
        .app DİZİNİNİ dosya sanıyordu ("Hedef dosya bulunamadi", "Is a
        directory"). Workspace üst workspace'tir: static stage ana bileşenin
        çıktılarını oraya taşır, reconstructed/ çıktıları da oraya yazılır
        (raporlar ve arayüz orayı okur).
        """
        from karadul.analyzers.app_bundle import (
            build_component_target,
            component_context,
        )

        errors: list[str] = []
        stats: dict = {}
        artifacts: dict[str, Path] = {}

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

        # Ana bileşen: static stage'in seçtiği (metadata ya da bundle_analysis
        # .json); bulunamazsa en çok fonksiyonu olan.
        main_path = (
            context.metadata.get("main_component")
            or bundle_data.get("main_component_path")
            or ""
        )
        main_comp = next(
            (c for c in successful_components if c.get("path") == main_path),
            None,
        )
        if main_comp is None:
            main_comp = max(successful_components, key=lambda c: c.get("functions", 0))
        main_type = main_comp.get("type", "macho_binary")

        stats["bundle_name"] = bundle_data.get("bundle_name", "")
        stats["total_components"] = len(component_results)
        stats["reconstructed_components"] = 0
        stats["main_component"] = main_comp.get("name", "")
        stats["main_component_path"] = main_comp.get("path", "")

        try:
            comp_target = build_component_target(
                main_comp, bundle_data.get("bundle_name", "") or context.target.name,
            )
            comp_context = component_context(context, comp_target)
        except Exception as exc:
            return StageResult(
                stage_name=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                stats=stats,
                errors=[f"Ana bileşen hedefi kurulamadı: {type(exc).__name__}: {exc}"],
            )

        main_ok = False

        def _merge(res: StageResult) -> None:
            nonlocal main_ok
            stats.update({k: v for k, v in res.stats.items() if k not in stats})
            errors.extend(res.errors)
            # P-S4: ana bileşenin hattı 'atlandı' ise (ör. Electron JS'inde
            # deobfuscation çıktısı yok) bundle aşaması nedensiz başarısız görünmesin.
            if res.skipped and (res.stats or {}).get("skip_reason"):
                errors.append(
                    f"Ana bileşen ({stats.get('main_component', '?')}) yeniden "
                    f"kurulmadı: {res.stats['skip_reason']}"
                )
            artifacts.update(res.artifacts)
            main_ok = main_ok or bool(res.success)

        # Ana bilesen tipine gore reconstruction metodu sec
        if main_type in ("macho_binary", "universal_binary", "elf_binary", "pe_binary"):
            try:
                stats["main_reconstruction"] = "binary"
                _merge(self._execute_binary(comp_context, start))
            except Exception as exc:
                errors.append(f"Ana bilesen reconstruction hatasi: {exc}")
        elif main_type == "go_binary":
            # v1.6.5: Go binary hybrid pipeline — bundle icinde de
            # Go + binary reconstruction birlikte calistir
            try:
                stats["main_reconstruction"] = "go_hybrid"
                _merge(self._execute_go_binary(comp_context, start))
                try:
                    _merge(self._execute_binary(comp_context, start))
                except Exception as exc:
                    logger.warning(
                        "Go hybrid bundle: binary recon basarisiz: %s", exc,
                    )
            except Exception as exc:
                errors.append(f"Go bilesen reconstruction hatasi: {exc}")
        elif main_type in ("electron_app", "js_bundle"):
            try:
                stats["main_reconstruction"] = "js"
                _merge(self._execute_js(comp_context, start))
            except Exception as exc:
                errors.append(f"JS bilesen reconstruction hatasi: {exc}")
        elif main_type in ("java_jar", "android_apk", "dotnet_assembly", "python_packed"):
            # BORU-08: JAR'ın kendi hattı (eskiden "Bilinmeyen bilesen tipi").
            try:
                stats["main_reconstruction"] = "analyzer"
                _merge(self._execute_analyzer_reconstruct(comp_context, start))
            except Exception as exc:
                errors.append(f"{main_type} bilesen reconstruction hatasi: {exc}")
        else:
            errors.append(f"Bilinmeyen bilesen tipi: {main_type}")

        # Yalnız ana bileşen reconstruct edilir; başarısızsa 0.
        stats["reconstructed_components"] = 1 if main_ok else 0

        logger.info(
            "Bundle reconstruction: %d/%d bilesen, ana=%s",
            stats["reconstructed_components"],
            len(successful_components),
            stats.get("main_component", "?"),
        )

        return StageResult(
            stage_name=self.name,
            success=main_ok,
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

    def _execute_analyzer_reconstruct(self, context: PipelineContext, start: float) -> StageResult:
        """Managed/bytecode format reconstruction — kayitli analizorun reconstruct() ile.

        JVM (JAR), Dalvik (APK) ve .NET (CIL) native binary DEGIL: Ghidra/JS yolu
        yerine registry'deki analizorun kendi reconstruct'i calisir (JavaBinaryAnalyzer:
        build.gradle + jadx varsa kaynak; DotNetBinaryAnalyzer: .csproj + ILSpy varsa
        kaynak). Fonksiyon sayisi static stage'in `functions` stat'inda (metot sayisi)
        tasinir -> "0 fonksiyon" + JS-iskelet misroute'u giderilir.

        get_analyzer(target_type) ile calistigindan tipe ozel degil: target_type ->
        analizor eslesmesi analyzers/__init__.py registry'sinde (JAVA_JAR/ANDROID_APK ->
        JavaBinaryAnalyzer, DOTNET_ASSEMBLY -> DotNetBinaryAnalyzer).
        """
        target_kind = context.target.target_type.value
        try:
            analyzer_cls = get_analyzer(context.target.target_type)
            analyzer = analyzer_cls(context.config)
            result = analyzer.reconstruct(context.target, context.workspace)
        except Exception as exc:
            logger.exception("%s reconstruction hatasi: %s", target_kind, exc)
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
                errors=[f"{target_kind} reconstruction sonuc dondurmedi (analiz JSON'u yok mu?)"],
            )
        result.stage_name = self.name
        self._note_decompiler_status(context, result)
        return result

    @staticmethod
    def _note_decompiler_status(context: PipelineContext, result: StageResult) -> None:
        """Kaynak decompile edilmediyse bunu açıkça yaz (P-S4: arac_yok, sahte başarı değil).

        JVM / .NET analizcileri static'te ``decompiled`` bayrağını yazar; jadx /
        ilspycmd yoksa reconstruct yine "reconstructed: true" ile yalnız proje iskeleti
        (build.gradle / .csproj) üretiyordu (gerçek örnekte JAR ×2, APK ×2: 1 dosya,
        hatasız 'başarılı'). İskelet kalır; durum ve neden kayda, aşama kısmi olur.
        """
        static = (getattr(context, "results", None) or {}).get("static")
        sstats = getattr(static, "stats", None) or {}
        if sstats.get("decompiled") is not False:
            return
        serrors = [str(e) for e in (getattr(static, "errors", None) or [])]
        missing = [e for e in serrors if "bulunamadi" in e or "bulunamadı" in e]
        reason = (missing or serrors or ["decompiler kaynak üretmedi"])[0]
        result.stats["decompiler_status"] = "arac_yok" if missing else "basarisiz"
        result.stats["decompiler_reason"] = reason
        result.stats["source_files_recovered"] = 0
        result.errors.append(
            f"Kaynak kod kurulmadı ({reason}); yalnız proje iskeleti yazıldı."
        )

    # ------------------------------------------------------------------
    # v1.12.0 Faz 2 split adim 1: Setup + Load alt metotlari.
    # Plan: docs/migrations/stages_split_plan.md §3 (metot 1).
    # Kural: Kese-yapistir + _ReconCtx kullanim. Mantik degismedi.
    # ------------------------------------------------------------------

    def _prepare_workspace(
        self, context: PipelineContext, rc: ReconstructionContext
    ) -> None:
        """_execute_binary Setup bolumu (plan §3 metot 1).

        Eski satirlar 1147-1156 karsiligi. Errors/artifacts/stats init,
        target + workspace dizinleri ``rc``'ye yazilir. Hicbir yan-etki
        yoktur — sadece dir path'leri cozulur (workspace.get_stage_dir
        idempotent).
        """

        rc.errors = []
        rc.artifacts = {}
        rc.stats = {}

        target = context.target
        static_dir = context.workspace.get_stage_dir("static")
        deob_dir = context.workspace.get_stage_dir("deobfuscated")
        reconstructed_dir = context.workspace.get_stage_dir("reconstructed")

        rc.static_dir = static_dir
        rc.reconstructed_dir = reconstructed_dir
        # deob_dir ``dirs`` sozlugunde, cunku ReconstructionContext'te
        # explicit alani yok (Faz 2 ilerisinde eklenebilir).
        rc.dirs["deobfuscated"] = deob_dir
        rc.dirs["static"] = static_dir
        rc.dirs["reconstructed"] = reconstructed_dir
        # workspace_dir: context.workspace.path (Workspace.path property).
        ws_root = getattr(context.workspace, "path", None)
        if ws_root is not None:
            rc.workspace_dir = Path(ws_root)
        bin_path = getattr(target, "path", None)
        if bin_path is not None:
            rc.binary_path = Path(bin_path)

    # ------------------------------------------------------------------
    # FIX-1 (2026-07-06): main'i __libc_start_main ilk argumanindan kurtar
    # ------------------------------------------------------------------

    _LIBC_START_MAIN_RE = re.compile(r"__libc_start_main\s*\(\s*(FUN_[0-9a-fA-F]+)")

    @staticmethod
    def _find_decompiled_dir(static_dir: "Path | None") -> "Path | None":
        """Ham FUN_*.c decompiled dizinini esnek bul.

        Reconstruct yolu (step-registry vs legacy vs deobfuscation) workspace
        yapisini degistiriyor: bazen ``static/ghidra_output/decompiled``, bazen
        ``deobfuscated/decompiled``. Sabit yol varsayimi bazi binary'lerde
        (ornegin cache'ten reuse edilen eski workspace) decompiled'i bulamayip
        FIX-1/FIX-2'yi sessizce devre disi birakiyordu. Bu yardimci
        ``static_dir`` ve ebeveyninde bilinen alt yollari, sonra FUN_*.c iceren
        ilk ``decompiled`` dizinini arar.
        """
        if static_dir is None:
            return None
        roots = [static_dir]
        if static_dir.parent and static_dir.parent != static_dir:
            roots.append(static_dir.parent)
        known = ("ghidra_output/decompiled", "deobfuscated/decompiled", "decompiled")
        for root in roots:
            for sub in known:
                d = root / sub
                if d.is_dir() and next(d.glob("FUN_*.c"), None) is not None:
                    return d
        for root in roots:
            for d in root.rglob("decompiled"):
                if d.is_dir() and next(d.glob("FUN_*.c"), None) is not None:
                    return d
        return None

    def _seed_recovery_pre_names(
        self,
        extracted_names: dict,
        static_dir: "Path | None",
        context: "PipelineContext",
        stats: dict,
        *,
        kesin: Any = None,
        meta: "dict | None" = None,
    ) -> dict:
        """Deterministik kurtarma isimlerini pre_names kanalina (extracted_names)
        enjekte eder ve manuel-override haritasini dondurur.

        Oncelik sirasi (TEK tanim -- CLAUDE.md §11, dagitik if yok):
          analist override > main (loader-kesin) > KS-1 kesin çapası > Faz 1 adları
          > gnulib fingerprint (upstream, GT-leakage yok) > ELF/CRT boilerplate.
          Çağrı sırası: main -> KS-1 -> gnulib -> boilerplate -> override. main ve
          override var olanı ezer, KS-1 yalnız korunmayan adı ezer, gnulib ve
          boilerplate yalnız boş yuvaya yazar; bu yüzden iki kez çağrı idempotent.

        ``kesin`` / ``meta`` (plan v2.2 N1 adım 3): ``kesin_anchors`` adımının
        bağlaması ve ön ad künyesi (anahtar -> tür). ``meta`` verilmezse KS-1
        uygulanmaz, künye tutulmaz: davranış eskisiyle aynıdır. Tohumların imzası
        değişmediği için tür, sözlüğün önceki ve sonraki hâli karşılaştırılarak
        bulunur; mantık ``tarif/baglama.py``'dedir.

        STEP REGISTRY TUZAGI (kok sebep, 2026-07-16): Bu tohum, Phase-2
        ``feedback_loop`` naming step'inden ONCE calismali. Aksi halde c_namer
        FUN_xxx'i davranissal sablonla (ol. ``version_output_version``,
        ``memory_exhausted``) yeniden adlandirir; recovery main'i sonradan
        extracted_names'e yazsa da AhoReplacer dosyada artik ``FUN_xxx`` literalini
        BULAMAZ -> main/gnulib cikti dosyasina ULASMAZ. Bu metot asama kodunda
        tek noktada (Phase-2 oncesi) cagrilir; Faz 2 sonrasindaki ikinci cagri
        P-S4'te (2026-11-19) kaldirildi. Iki kez cagrilmasi yine idempotenttir.
        """
        if not isinstance(extracted_names, dict):
            return {}
        if meta is None:
            self._recover_main_from_entry(extracted_names, static_dir, stats,
                                          getattr(context, "config", None))
            self._recover_gnulib_from_fingerprints(extracted_names, static_dir, stats)
            self._recover_elf_boilerplate(extracted_names, static_dir, stats)
            return self._apply_manual_overrides(extracted_names, context, stats)

        from karadul.reconstruction.tarif import baglama as _bg

        # Künyesi olmayan mevcut adlar Faz 1'den (BinaryNameExtractor, byte pattern, CAPA).
        _bg.mark_changed(
            meta, {}, {k: v for k, v in extracted_names.items() if k not in meta},
            _bg.KIND_PHASE1,
        )
        before = dict(extracted_names)
        self._recover_main_from_entry(extracted_names, static_dir, stats,
                                      getattr(context, "config", None))
        _bg.mark_changed(meta, before, extracted_names, _bg.KIND_MAIN)
        _bg.apply_binding(extracted_names, kesin, meta, stats)
        before = dict(extracted_names)
        self._recover_gnulib_from_fingerprints(extracted_names, static_dir, stats)
        _bg.mark_changed(meta, before, extracted_names, _bg.KIND_GNULIB)
        before = dict(extracted_names)
        self._recover_elf_boilerplate(extracted_names, static_dir, stats)
        _bg.mark_changed(meta, before, extracted_names, _bg.KIND_ELF_BOILERPLATE)
        manual_map = self._apply_manual_overrides(extracted_names, context, stats)
        for key, name in manual_map.items():
            meta[key] = _bg.make_meta(_bg.KIND_MANUAL, name)
        return manual_map

    def _recover_main_from_entry(
        self, extracted_names: dict, static_dir: "Path | None", stats: dict,
        config: Any = None,
    ) -> None:
        """``main``'i entry/_start icindeki ``__libc_start_main`` cagrisindan kurtar.

        Stripped ELF'te program giris noktasi (``entry``/``_start``)
        ``__libc_start_main(main, argc, argv, ...)`` cagirir; ilk arguman
        main'in adresidir (glibc x86-64 + ARM64 ayni ABI). Ghidra bunu
        ``__libc_start_main(FUN_xxxx, ...)`` olarak decompile eder -> FUN_xxxx = main.
        Bu, loader'in main'i buldugu yontemin ta kendisi; pratikte kesin,
        deterministik, arch-bagimsiz (ham decompile C'sinden okunur, LLM yok).

        Davranissal namer main'i sistematik olarak yanlis isimlendiriyordu
        (ol. ``version_output_version``, ``argv_passed_through``). Isim ``pre_names``
        kanalina (``extracted_names``) yazilir; c_namer guard'i
        (``if old_name in naming_map: continue``) davranissalin ezmesini engeller.

        NOT: Cagri ``_seed_recovery_pre_names`` uzerinden (Faz 2 oncesi tohum)
        yapilir; ``extracted_names`` local dict'i dogrudan mutasyona
        ugratilir. Ham FUN_ adresleri icin ``static_dir/ghidra_output/decompiled``
        (Ghidra ciktisinin isim-degismemis hali) kullanilir.

        P-ÜV5 (2026-11-23): kalıp bulunamazsa ve bayrak
        ``binary_reconstruction.enable_macho_entry_main`` gerçek ``True`` ise Mach-O kuralı
        (``_recover_macho_entry_main``) denenir: ``LC_MAIN`` girişi geliştiricinin ``main``'idir.
        ELF yolu değişmez; bayrak kapalıyken davranış eskisiyle bayt bayt aynıdır.
        """
        try:
            if not isinstance(extracted_names, dict) or static_dir is None:
                return
            decompiled_dir = self._find_decompiled_dir(static_dir)
            if decompiled_dir is None:
                return

            main_addr: str | None = None
            # entry/_start genelde kucuk; ismi entry/start iceren dosyalari
            # oncelikle tara, yoksa tum .c dosyalarina bak.
            c_files = list(decompiled_dir.rglob("*.c"))
            c_files.sort(key=lambda p: (0 if ("entry" in p.stem.lower()
                                              or "start" in p.stem.lower()) else 1))
            for c in c_files:
                try:
                    txt = c.read_text(errors="ignore")
                except Exception:
                    continue
                m = self._LIBC_START_MAIN_RE.search(txt)
                if m:
                    main_addr = m.group(1)
                    break
            if not main_addr:
                if self._macho_entry_main_enabled(config):
                    self._recover_macho_entry_main(
                        extracted_names, static_dir, decompiled_dir, stats)
                return

            prev = extracted_names.get(main_addr)
            if prev == "main":
                return
            # main-from-libc_start_main loader-kesinligindedir -> onceki
            # (davranissal/CAPA) ismi EZER.
            extracted_names[main_addr] = "main"
            stats["main_recovered"] = main_addr
            logger.info(
                "main kurtarildi: %s -> main (__libc_start_main arg0)%s",
                main_addr, f" [onceki: {prev}]" if prev else "",
            )
        except Exception as exc:  # pragma: no cover -- savunmaci
            logger.debug("main kurtarma (entry) hatasi: %s", exc)

    # ------------------------------------------------------------------
    # P-ÜV5 (2026-11-23): Mach-O ``LC_MAIN`` girişi = ``main``
    # ------------------------------------------------------------------
    # Mach-O çalıştırılabilirinde (``MH_EXECUTE``) yükleyici ``LC_MAIN``'in ``entryoff``'unu çağırır;
    # bu adres geliştiricinin ``main``'idir (ölçüldü: GT'li 8 / 8, Homebrew 1 169 / 1 169;
    # ``docs/arge/2026-11-19_mythos/ustveri/PLAN.md`` "P-ÜV5"). Ad yükleyici alanından gelir ve
    # çalışma için zorunludur: künye ``main_giris`` (ELF yoluyla aynı), ``üst veriden`` değil.
    # Ad yazılmayan durumlarda neden ``stats["macho_entry_main"]``'a yazılır (kanıt satırı).

    MACHO_MAIN_STATS_KEY = "macho_entry_main"
    _MH_EXECUTE = 2                       # mach-o/loader.h ``MH_EXECUTE``
    _GO_DEVELOPER_MAIN = "main.main"      # Go'da geliştiricinin main'i; giriş ``_rt0_…`` / saplama

    @staticmethod
    def _macho_entry_main_enabled(config: Any) -> bool:
        """Bayrak yalnız gerçek ``True`` ise açık (``"true"``, 1, sahte nesne açmaz)."""
        recon = getattr(config, "binary_reconstruction", None)
        return getattr(recon, "enable_macho_entry_main", False) is True

    @staticmethod
    def _parse_int(value: str) -> int | None:
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        except ValueError:
            return None

    @classmethod
    def _parse_macho_load_commands(cls, text: str) -> dict:
        """``otool -l`` çıktısından (``static/load_commands.txt``) giriş bilgisi.

        Dönen: ``entryoffs`` (her ``LC_MAIN`` bloğunun ``entryoff``'u), ``unixthread``
        (``LC_UNIXTHREAD`` var mı), ``unixthread_pcs`` (o bloktaki ``pc`` / ``rip`` yazmacı; mutlak
        adres, yalnız kanıt), ``text_vmaddr`` (``__TEXT`` bölütünün ``vmaddr``'ı; ikilinin bağlama
        tabanı). Okunamayan alan ``None`` / boş kalır; tahmin yok.
        """
        entryoffs: list[int | None] = []
        unixthread = False
        unixthread_pcs: list[int | None] = []
        text_vmaddr: int | None = None
        cmd: str | None = None
        segname: str | None = None
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            key, val = parts[0], parts[1]
            if key == "cmd":
                cmd, segname = val, None
                if val == "LC_UNIXTHREAD":
                    unixthread = True
            elif key == "segname" and cmd in ("LC_SEGMENT_64", "LC_SEGMENT"):
                segname = val
            elif key == "vmaddr" and segname == "__TEXT" and text_vmaddr is None:
                text_vmaddr = cls._parse_int(val)
            elif key == "entryoff" and cmd == "LC_MAIN":
                entryoffs.append(cls._parse_int(val))
            elif cmd == "LC_UNIXTHREAD":
                for i, tok in enumerate(parts[:-1]):
                    if tok in ("pc", "rip"):
                        unixthread_pcs.append(cls._parse_int(parts[i + 1]))
        return {"entryoffs": entryoffs, "unixthread": unixthread,
                "unixthread_pcs": unixthread_pcs, "text_vmaddr": text_vmaddr}

    @staticmethod
    def _ghidra_image_base(static_dir: Path) -> int | None:
        """Ghidra'nın görüntü tabanı (``program_info.image_base``, onaltılık); yoksa ``None``."""
        for path in (static_dir / "ghidra_combined_results.json",
                     static_dir / "ghidra_output" / "combined_results.json"):
            try:
                if not path.is_file():
                    continue
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                info = data.get("program_info") or (data.get("summary") or {}).get("program") or {}
                raw = info.get("image_base")
                if raw:
                    return int(str(raw), 16)
            except (OSError, ValueError, TypeError, AttributeError):
                continue
        return None

    @staticmethod
    def _open_macho_image(static_dir: Path) -> Any:
        """Ürünün analiz ettiği ince dilimi P-ÜV0 görüntüsü olarak aç; olmazsa ``None``.

        Sıra: ``static/universal_slice.json``'un seçtiği dilim (``raw/<ad>_<mimari>``), çalışma
        alanındaki kopya (``raw/<ad>``), hedefin yolu (``raw/target_info.json``). Evrensel dosyada
        ürünün seçtiği dilim (``goruntu.urun_dilimi``) açılır.
        """
        from karadul.analyzers.ustveri import goruntu

        raw_dir = static_dir.parent / "raw"
        candidates: list[Path] = []
        try:
            sl = json.loads((static_dir / "universal_slice.json").read_text(encoding="utf-8"))
            if isinstance(sl, dict) and sl.get("path"):
                candidates.append(raw_dir / Path(str(sl["path"])).name)
        except (OSError, ValueError, TypeError):
            pass
        try:
            ti = json.loads((raw_dir / "target_info.json").read_text(encoding="utf-8"))
            if isinstance(ti, dict):
                if ti.get("name"):
                    candidates.append(raw_dir / Path(str(ti["name"])).name)
                if ti.get("path"):
                    candidates.append(Path(str(ti["path"])))
        except (OSError, ValueError, TypeError):
            pass
        for cand in candidates:
            if not cand.is_file():
                continue
            try:
                veri = cand.read_bytes()
                return goruntu.baytlardan(veri, goruntu.urun_dilimi(veri), kaynak=str(cand))
            except Exception:  # noqa: BLE001 - görüntü kurulamazsa kural ad yazmaz
                return None
        return None

    @classmethod
    def _go_entry_block(cls, image: Any, entry_bin: int) -> tuple[str | None, str | None]:
        """Go istisnası (gönderim hüküm 2): (engel nedeni ya da ``None``, girişin ``pclntab`` adı).

        Okuyucu ürünün kendisi (``karadul/analyzers/ustveri/go_pclntab.py``). ``pclntab`` yoksa
        (``veri_yok``) engel yok. Varsa yalnız girişin ``pclntab`` adı ``main.main`` ise ad yazılır:
        iç bağlayıcılı Go'da giriş ``_rt0_…``, dış bağlayıcılıda Go'nun ``main`` saplaması
        (geliştiricinin ``main``'i değil). Okuyucu başka durum verirse (``tutarsiz``,
        ``desteklenmiyor``, ``hata``) Go olmadığı gösterilemez: ad yazılmaz.
        """
        from karadul.analyzers.ustveri import go_pclntab

        sonuc = go_pclntab.oku(image)
        if sonuc.durum == go_pclntab.DURUM_VERI_YOK:
            return None, None
        if sonuc.durum != go_pclntab.DURUM_CALISTI:
            return f"go_okunamadi:{sonuc.durum}", None
        for f in sonuc.fonksiyonlar:
            if f.giris <= entry_bin < f.bitis:
                if f.ad == cls._GO_DEVELOPER_MAIN:
                    return None, f.ad
                return "go_giris_main_main_degil", f.ad
        return "go_giris_pclntab_disinda", None

    def _recover_macho_entry_main(
        self, extracted_names: dict, static_dir: Path, decompiled_dir: Path, stats: dict
    ) -> None:
        """Mach-O kuralı (P-ÜV5): ``LC_MAIN`` girişindeki jenerik adlı fonksiyona ``main``.

        Koşullar (hepsi): ``static/load_commands.txt`` var (yalnız Mach-O'da yazılır); tek bir
        ``LC_MAIN`` ``entryoff``'u; ikili Mach-O ``MH_EXECUTE``; Ghidra'nın giriş adresindeki
        fonksiyonu jenerik adlı (``entry`` / ``FUN_…``; ``kesin.is_generic_name``) ve kodu
        decompile çıktısında; Go istisnası engel değil. Giriş adresi: Ghidra adresi = ikili adresi
        (``__TEXT`` ``vmaddr`` + ``entryoff``) + görüntü tabanı farkı (``GhidraFunctionIndex.delta``).
        Thunk girişte adı thunk alır (hedefi değil). ``LC_UNIXTHREAD`` (eski düzen, giriş
        ``start``) ad almaz. Anahtar Ghidra'nın adıdır (kodda geçen ad).
        """
        lc_path = static_dir / "load_commands.txt"
        if not lc_path.is_file():
            return  # Mach-O değil: ELF / PE yolunda kayıt da yazılmaz
        from karadul.pipeline.steps._feedback_naming_candidates import load_ghidra_index
        from karadul.reconstruction.tarif.kesin import is_generic_name

        rec: dict[str, Any] = {"durum": "yazilmadi"}
        stats[self.MACHO_MAIN_STATS_KEY] = rec
        info = self._parse_macho_load_commands(lc_path.read_text(errors="replace"))
        offs = info["entryoffs"]
        if not offs:
            # LC_UNIXTHREAD (eski düzen): giriş ``start``'tır (crt), ``main`` değil -> kanıt satırı
            rec["neden"] = "lc_unixthread" if info["unixthread"] else "lc_main_yok"
            pcs = [p for p in info["unixthread_pcs"] if p is not None]
            if pcs:
                rec["unixthread_pc"] = hex(pcs[0])
            return
        if len(set(offs)) != 1 or offs[0] is None:
            rec["neden"] = "lc_main_belirsiz"
            return
        entryoff = int(offs[0])
        text_vmaddr = info["text_vmaddr"]
        image_base = self._ghidra_image_base(static_dir)
        if text_vmaddr is None or image_base is None:
            rec["neden"] = "taban_okunamadi"
            return
        image = self._open_macho_image(static_dir)
        if image is None or getattr(image, "bicim", None) != "macho":
            rec["neden"] = "ikili_okunamadi"
            return
        if getattr(image, "dosya_turu", None) != self._MH_EXECUTE:
            rec["neden"] = "mh_execute_degil"
            return
        functions_json = static_dir / "ghidra_functions.json"
        if not functions_json.is_file():
            functions_json = static_dir / "ghidra_output" / "functions.json"
        index = load_ghidra_index(functions_json)
        if index is None:
            rec["neden"] = "ghidra_fonksiyon_listesi_yok"
            return
        index.delta = image_base - text_vmaddr
        entry_bin = text_vmaddr + entryoff
        entry_ghidra = entry_bin + index.delta
        rec["giris"] = hex(entry_ghidra)
        name = index.by_addr.get(entry_ghidra)
        if name is None:
            rec["neden"] = "ghidra_fonksiyonu_yok"
            return
        rec["ghidra_adi"] = name
        if not is_generic_name(name):
            rec["neden"] = "ghidra_adli"
            return
        if not (decompiled_dir / f"{name}.c").is_file():
            rec["neden"] = "kodda_yok"
            return
        block, go_name = self._go_entry_block(image, entry_bin)
        if go_name is not None:
            rec["go_adi"] = go_name
        if block is not None:
            rec["neden"] = block
            return
        rec.update(durum="yazildi", anahtar=name, kanit=(
            f"LC_MAIN entryoff {entryoff} + Ghidra görüntü tabanı {image_base:#x} "
            f"= {entry_ghidra:#x} ({name})"))
        prev = extracted_names.get(name)
        if prev == "main":
            return
        # LC_MAIN yükleyici kesinliğindedir (ELF yolundaki __libc_start_main gibi): önceki adı EZER.
        extracted_names[name] = "main"
        stats["main_recovered"] = name
        logger.info("main kurtarildi: %s -> main (Mach-O LC_MAIN)%s",
                    name, f" [onceki: {prev}]" if prev else "")

    def _recover_gnulib_from_fingerprints(
        self, extracted_names: dict, static_dir: "Path | None", stats: dict
    ) -> None:
        """gnulib kutuphane fonksiyonlarini string-anchor fingerprint ile kurtar.

        FIX-2 (2026-07-08). coreutils stripped-ELF'te gnulib fonksiyonlari
        (``xalloc_die``, ``version_etc``, ``close_stdout`` ...) ``.constprop``/
        ``.isra`` ile inline+specialize edildigi icin byte-imza backbone'u OLU.
        Tek ayirt-edici sinyal, referansladiklari sabit string mesajlaridir
        (``"memory exhausted"`` -> ``xalloc_die`` vb.). Fingerprint DB
        (``karadul.analyzers.gnulib_fingerprints``) isim eslemesini gnulib
        UPSTREAM kaynagindan turetir, test binary'sinden DEGIL (GT-leakage yok).

        Precision icin **unique-in-binary** kisiti: bir gnulib adi yalniz TEK
        ``FUN_`` ile eslesirse atanir; birden fazla aday varsa belirsiz kabul
        edilip call-shape katmanina (FIX-2b) birakilir.

        P-S3 (AD-03, B-A3; 2026-11-18) iki kanıt koşulu, tek karar noktasında (``_offer``):
          1. **gnulib varlık kanıtı**: ikilide en az ``MIN_PRESENCE_MODULES`` bağımsız gnulib
             modülünün işareti yoksa (``presence_evidence``) kanal hiç ad yazmaz. Eskiden
             gnulib'siz programlarda da ateşleniyordu (tmux ``close_stdout``, redis-cli
             ``full_write``; Mach-O dahil).
          2. **LTO yerleşimi**: ``version_etc`` / ``hard_locale`` / ``full_write`` ateşlendiği
             fonksiyonun bütün çağıranları ince sarmalayıcıysa (``lto_less_layout``) ad
             yazılmaz: LTO'suz yapıda dizgi / çağrı iç fonksiyonda kalır, ad yanlış olurdu.
        Yazılmayan aday kaybolmaz: kanıt satırı ve nedeniyle ``static/gnulib_candidates.json``'a
        yazılır (uygulananlar da kanıtıyla); varlık kanıtı ``stats["gnulib_evidence"]``'da.
        Bir katmanın önerdiği anahtar (uygulansın ya da tutulsun) sonraki gnulib katmanlarına
        aday olmaz: tutulan bir dizgi adayı zayıf bir çağrı şekliyle yeniden adlanmaz.

        Isim ``pre_names`` kanalina (``extracted_names``) yazilir; c_namer guard'i
        davranissal namer'in ezmesini engeller (``_recover_main_from_entry`` ile
        ayni mekanizma). Onceden atanmis pre_name'ler (FIX-1 ``main`` dahil) EZILMEZ.
        Iki kez cagri idempotent: ad zaten ayniysa yeniden yazilmaz, karar kaydi ayni kalir.
        """
        try:
            if not isinstance(extracted_names, dict) or static_dir is None:
                return
            decompiled_dir = self._find_decompiled_dir(static_dir)
            if decompiled_dir is None:
                return
            from karadul.analyzers.gnulib_fingerprints import (
                GNULIB_CALL_SHAPES,
                GNULIB_DISAMBIGUATORS,
                GNULIB_FINGERPRINTS,
                LAYOUT_DEPENDENT_NAMES,
                MIN_PRESENCE_MODULES,
                THIN_CALLER_MAX_CALLEES,
                USAGE_CONVENTION_NAME,
                disambiguate,
                extract_string_literals,
                lto_less_inner_name,
                lto_less_layout,
                match_call_shape,
                match_function,
                presence_evidence,
            )

            # name -> [fun_key, ...]  (unique-in-binary degerlendirmesi icin). Ayni taramada
            # ikilinin BUTUN dizgi degismezleri toplanir (P-S3: varlik kaniti). Dosyalar sirali
            # taranir: aday listeleri ve ekleme sirasi dosya sistemine bagli olmasin.
            candidates: dict[str, list[str]] = {}
            all_literals: set[str] = set()
            for c in sorted(decompiled_dir.rglob("*.c")):
                try:
                    txt = c.read_text(errors="ignore")
                except Exception:
                    continue
                literals = extract_string_literals(txt)
                all_literals.update(literals)
                fun_key = c.stem  # dosya adi = kanonik FUN_00xxxxxx
                if not fun_key.startswith("FUN_"):
                    continue
                name = match_function(literals)
                if name == "version_etc" and "getopt_long" in txt:
                    # FIX-4 (2026-07-12): "Written by" string'i normalde version_etc'e
                    # aittir; ama parse_long_options, --version isini .constprop ile
                    # inline ettiginde o string parse_long_options govdesine tasinir.
                    # Ayirt-edici: parse_long_options getopt_long cagirir, version_etc
                    # CAGIRMAZ -> getopt_long varsa bu FUN parse_long_options'tir.
                    # version_etc atamasini iptal et (call-shape katmani, getopt_long
                    # fingerprint'i ile parse_long_options'i dogru atar).
                    name = None
                if name:
                    candidates.setdefault(name, []).append(fun_key)

            # Cagri cizgesi: varlik kaniti (cagrilan adlar), call-shape ve yerlesim (cagiranlar).
            cg_path = None
            _roots = [static_dir]
            if static_dir.parent and static_dir.parent != static_dir:
                _roots.append(static_dir.parent)
            for _root in _roots:
                found = next(_root.rglob("call_graph.json"), None)
                if found is not None:
                    cg_path = found
                    break
            nodes: dict = {}
            if cg_path is not None:
                try:
                    nodes = json.loads(cg_path.read_text()).get("nodes", {}) or {}
                except Exception:
                    nodes = {}
            node_by_key: dict[str, dict] = {}
            callees_by_key: dict[str, set[str]] = {}
            all_callees: set[str] = set()
            for addr_key, node in nodes.items():
                if not isinstance(node, dict):
                    continue
                try:
                    fk = f"FUN_{int(str(addr_key), 16):08x}"
                except (ValueError, TypeError):
                    continue
                names = {
                    c.get("name", "")
                    for c in node.get("callees", [])
                    if isinstance(c, dict)
                }
                node_by_key[fk] = node
                callees_by_key[fk] = names
                all_callees.update(names)

            presence = presence_evidence(all_literals, all_callees)
            presence_line = presence.evidence_line()
            decisions: list[dict] = []
            proposed: set[str] = set()

            def _caller_counts(fk: str) -> list[int]:
                counts: list[int] = []
                for caller in (node_by_key.get(fk) or {}).get("callers", []) or []:
                    if not isinstance(caller, dict):
                        continue
                    try:
                        ck = f"FUN_{int(str(caller.get('address')), 16):08x}"
                    except (ValueError, TypeError):
                        continue
                    if ck in node_by_key:
                        counts.append(int(node_by_key[ck].get("callee_count", 0)))
                return counts

            def _main_caller(fk: str) -> str | None:
                """P-S3b kalem 2: adayı entry'den kurtarılan ``main`` doğrudan çağırıyor mu."""
                for caller in (node_by_key.get(fk) or {}).get("callers", []) or []:
                    if not isinstance(caller, dict):
                        continue
                    try:
                        ck = f"FUN_{int(str(caller.get('address')), 16):08x}"
                    except (ValueError, TypeError):
                        continue
                    if extracted_names.get(ck) == "main":
                        return ck
                return None

            def _offer(fk: str, nm: str, channel: str, evidence: str) -> bool:
                """Tek karar noktasi: adi yaz ya da gerekcesiyle tut; yazildiysa True."""
                proposed.add(fk)
                rec: dict = {"key": fk, "name": nm, "channel": channel, "evidence": evidence}
                current = extracted_names.get(fk)
                inner = lto_less_inner_name(nm) if nm in LAYOUT_DEPENDENT_NAMES else None
                if current is not None and current != nm and current != inner:
                    rec.update(decision="skipped", reason="on_ad_dolu", existing=current)
                    decisions.append(rec)
                    return False
                if not presence.sufficient:
                    main_key = _main_caller(fk) if nm == USAGE_CONVENTION_NAME else None
                    if main_key is None:
                        rec.update(decision="withheld", reason="gnulib_kaniti_yetersiz",
                                   evidence_presence=presence_line)
                        decisions.append(rec)
                        return False
                    # P-S3b kalem 2: usage gnulib fonksiyonu değil, gelenek; iki bağımsız kanıt
                    # (tek "Usage: %s" fonksiyonu + main onu doğrudan çağırıyor).
                    rec.update(decision="applied", reason="usage_gelenegi",
                               evidence_convention=(f"gnulib varlık kanıtı yok; 'Usage: %s' tek "
                                                    f"fonksiyonda ve main ({main_key}) onu "
                                                    f"doğrudan çağırıyor"))
                    decisions.append(rec)
                    if current == nm:
                        return False
                    extracted_names[fk] = nm
                    return True
                if nm in LAYOUT_DEPENDENT_NAMES:
                    counts = _caller_counts(fk)
                    if lto_less_layout(counts) and inner is not None:
                        # P-S3b kalem 4: LTO'suz yerleşimde dizgi / çağrı iç fonksiyonda; iç adı yaz.
                        rec.update(
                            decision="applied", reason="lto_yerlesimi_ic_ad", name=inner,
                            outer_name=nm, caller_callee_counts=counts,
                            evidence_layout=(
                                f"çağıranların hepsi ince sarmalayıcı (≤ {THIN_CALLER_MAX_CALLEES} "
                                f"çağrı; çağrı sayıları {counts}): LTO'suz yerleşim, dizgi / çağrı "
                                f"{nm}'in iç fonksiyonunda -> {inner}"
                            ),
                        )
                        decisions.append(rec)
                        if current == inner:
                            return False
                        extracted_names[fk] = inner
                        return True
                    if lto_less_layout(counts):
                        rec.update(
                            decision="withheld", reason="lto_yerlesimi",
                            caller_callee_counts=counts,
                            evidence_layout=(
                                f"çağıranların hepsi ince sarmalayıcı (≤ {THIN_CALLER_MAX_CALLEES} "
                                f"çağrı; çağrı sayıları {counts}): LTO'suz yerleşim, "
                                f"{nm} adı bu fonksiyonun değil onu çağıranın"
                            ),
                        )
                        decisions.append(rec)
                        return False
                rec.update(decision="applied")
                decisions.append(rec)
                if current == nm:
                    return False  # ikinci cagri: ad zaten yazili (idempotent)
                extracted_names[fk] = nm
                return True

            fp_by_name = {fp.name: fp for fp in GNULIB_FINGERPRINTS}
            cs_by_name = {cs.name: cs for cs in GNULIB_CALL_SHAPES}
            dis_by_name = {d.name: d for d in GNULIB_DISAMBIGUATORS}

            assigned = 0
            ambiguous: list[str] = []
            for name, keys in candidates.items():
                if len(keys) != 1:
                    ambiguous.append(name)  # belirsiz -> call-shape'e (FIX-2b) birak
                    continue
                fun_key = keys[0]
                fp = fp_by_name[name]
                if _offer(fun_key, name, "dizgi_parmak_izi",
                          f"dizgi parmak izi {list(fp.anchors)} ({fp.source}); ikilide tek aday"):
                    assigned += 1
            if assigned:
                stats["gnulib_recovered"] = assigned
            if ambiguous:
                stats["gnulib_ambiguous"] = ambiguous
            if assigned:
                logger.info(
                    "gnulib fingerprint: %d fonksiyon kurtarildi%s",
                    assigned,
                    f" (belirsiz atlandi: {ambiguous})" if ambiguous else "",
                )

            # --- FIX-2b (2026-07-09): CALL-SHAPE katmani ---
            # String sabiti olmayan/paylasan gnulib fonksiyonlari icin ikinci
            # kanal: cagirdiklari ayirt-edici libc callee'leri (close_stream ->
            # __fpending, gettext_quote -> nl_langinfo). String-fp'den SONRA
            # calisir; zaten isimlenmis (main/string) ya da string-fp'nin onerdigi
            # fonksiyonlar aday sayilmaz.
            if cg_path is not None:
                cs_candidates: dict[str, list[str]] = {}
                for fun_key, node in node_by_key.items():
                    if fun_key in proposed:
                        continue
                    nm = match_call_shape(callees_by_key[fun_key],
                                          int(node.get("callee_count", 0)))
                    if not nm:
                        continue
                    current = extracted_names.get(fun_key)
                    if current is not None and current not in (nm, lto_less_inner_name(nm)):
                        continue  # zaten isimli (main/string-fp) -> aday degil
                    cs_candidates.setdefault(nm, []).append(fun_key)
                cs_assigned = 0
                for nm, keys in cs_candidates.items():
                    if len(keys) != 1:
                        continue  # unique-in-binary
                    fk = keys[0]
                    cs = cs_by_name[nm]
                    fanout = int(node_by_key[fk].get("callee_count", 0))
                    if _offer(fk, nm, "cagri_bicimi",
                              f"çağrı şekli: {list(cs.required_callees)} çağırır, çağrı sayısı "
                              f"{fanout} ({cs.source}); ikilide tek aday"):
                        cs_assigned += 1
                if cs_assigned:
                    stats["gnulib_callshape_recovered"] = cs_assigned
                    logger.info(
                        "gnulib call-shape: %d fonksiyon kurtarildi", cs_assigned
                    )

                # --- DISAMBIGUATION (2026-07-14): belirsiz string-fp adlari ---
                # Yukaridaki string-fp dongusu bir isim >1 FUN_'a eslesince
                # "ambiguous"a atip ATLIYOR (unique-in-binary). Tek gercek
                # belirsiz vaka: close_stdout vs write_error (ikisi de "write
                # error" tasir; 6 binary'de -- cat/cut/paste/split/tail/tr). Bu
                # post-pass ayirt-edici callee davranisiyla (close_stdout: _exit
                # VAR, __fpurge/clearerr_unlocked YOK) dogru adayi kurtarir.
                # Savunmaci: yalniz TEK aday hayatta kalirsa VE hedef hala
                # isimsizse atar -> wrong->correct duzeltmesi, dusus-risksiz.
                if ambiguous:
                    disamb_assigned = 0
                    for amb_name in ambiguous:
                        cand_fks = candidates.get(amb_name, [])
                        if len(cand_fks) < 2:
                            continue
                        cands = {
                            fk: callees_by_key.get(fk, set()) for fk in cand_fks
                        }
                        winner = disambiguate(amb_name, cands)
                        if not winner or winner in proposed:
                            continue
                        current = extracted_names.get(winner)
                        if current is not None and current != amb_name:
                            continue
                        rule = dis_by_name[amb_name]
                        if _offer(winner, amb_name, "ayristirma",
                                  f"dizgi parmak izi {len(cand_fks)} adayda; ayrıştırma: "
                                  f"{list(rule.require_callees)} çağırır, "
                                  f"{list(rule.exclude_callees)} çağırmaz ({rule.source})"):
                            disamb_assigned += 1
                    if disamb_assigned:
                        stats["gnulib_disambiguated"] = disamb_assigned
                        logger.info(
                            "gnulib disambiguation: %d fonksiyon kurtarildi",
                            disamb_assigned,
                        )

            withheld = [d for d in decisions if d["decision"] == "withheld"]
            stats["gnulib_evidence"] = {
                "sufficient": presence.sufficient,
                "modules": [m for m, _src, _kind, _anchor in presence.found],
                "min_modules": MIN_PRESENCE_MODULES,
            }
            if withheld:
                stats["gnulib_withheld"] = len(withheld)
                logger.info(
                    "gnulib: %d aday yazılmadı (%s); kanıtlarıyla gnulib_candidates.json'da",
                    len(withheld),
                    ", ".join(sorted({d["reason"] for d in withheld})),
                )
            self._write_gnulib_candidates(static_dir, presence, presence_line, decisions,
                                          ambiguous, candidates)
        except Exception as exc:  # pragma: no cover -- savunmaci
            logger.debug("gnulib fingerprint kurtarma hatasi: %s", exc)

    GNULIB_CANDIDATES_FILE = "gnulib_candidates.json"

    @classmethod
    def _write_gnulib_candidates(cls, static_dir: Path, presence: Any, presence_line: str,
                                 decisions: list, ambiguous: list, candidates: dict) -> None:
        """gnulib kanalının kararlarını kanıt satırlarıyla ``static/``'e yaz (K-2: aday kaybolmaz).

        Biçim (``schema_version`` 1): varlık kanıtı (modüller, eşik, kanıt satırı), her öneri
        için karar (``applied`` / ``withheld`` / ``skipped``), neden, kanıt satırı; belirsiz adlar
        ve aday anahtarları. Ad ve anahtar ürün koşusunun kendi verisidir (GT yok).
        """
        from karadul.analyzers.gnulib_fingerprints import (
            LAYOUT_DEPENDENT_NAMES,
            MIN_PRESENCE_MODULES,
            THIN_CALLER_MAX_CALLEES,
        )

        doc = {
            "schema": "karadul.gnulib_candidates",
            "schema_version": 1,
            "presence": {
                "sufficient": presence.sufficient,
                "min_modules": MIN_PRESENCE_MODULES,
                "found": [
                    {"module": m, "source": src, "kind": kind, "anchor": anchor}
                    for m, src, kind, anchor in presence.found
                ],
                "evidence": presence_line,
            },
            "layout_rule": {
                "names": sorted(LAYOUT_DEPENDENT_NAMES),
                "thin_caller_max_callees": THIN_CALLER_MAX_CALLEES,
            },
            "decisions": decisions,
            "ambiguous": {nm: list(candidates.get(nm, [])) for nm in ambiguous},
        }
        try:
            (static_dir / cls.GNULIB_CANDIDATES_FILE).write_text(
                json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        except OSError as exc:
            logger.warning("gnulib aday kaydı yazılamadı (%s): %s", static_dir, exc)

    def _recover_elf_boilerplate(
        self, extracted_names: dict, static_dir: "Path | None", stats: dict
    ) -> None:
        """ELF/CRT boilerplate fonksiyonlarini call-shape ile kurtar.

        FIX-3 (2026-07-12). Her ELF'te linker/CRT'nin urettigi sabit stub'lar
        (``register_tm_clones``, ``deregister_tm_clones``,
        ``__do_global_dtors_aux``, ``_start`` ...) stripped binary'de isimsiz
        ``FUN_`` olur ama davranislari -- cagirdiklari ayirt-edici runtime
        sembolleri (``_ITM_*``, ``__cxa_finalize``, ``__libc_start_main``) --
        evrenseldir ve kaynak-bagimsizdir -> deterministik hesaplanabilir.
        gnulib call-shape (FIX-2b) ile ayni mekanizma + unique-in-binary;
        onceki pre_name'ler (main/gnulib) EZILMEZ.
        """
        try:
            if not isinstance(extracted_names, dict) or static_dir is None:
                return
            from karadul.analyzers.elf_boilerplate import match_boilerplate

            cg_path = None
            _roots = [static_dir]
            if static_dir.parent and static_dir.parent != static_dir:
                _roots.append(static_dir.parent)
            for _root in _roots:
                found = next(_root.rglob("call_graph.json"), None)
                if found is not None:
                    cg_path = found
                    break
            if cg_path is None:
                return
            import json as _json

            try:
                nodes = _json.loads(cg_path.read_text()).get("nodes", {})
            except Exception:
                return
            bp_candidates: dict[str, list[str]] = {}
            for addr_key, node in nodes.items():
                if not isinstance(node, dict):
                    continue
                try:
                    fun_key = f"FUN_{int(str(addr_key), 16):08x}"
                except (ValueError, TypeError):
                    continue
                if extracted_names.get(fun_key) is not None:
                    continue  # zaten isimli (main/gnulib) -> aday degil
                callees = {
                    c.get("name", "")
                    for c in node.get("callees", [])
                    if isinstance(c, dict)
                }
                nm = match_boilerplate(callees, int(node.get("callee_count", 0)))
                if nm:
                    bp_candidates.setdefault(nm, []).append(fun_key)
            bp_assigned = 0
            for nm, keys in bp_candidates.items():
                if len(keys) != 1:
                    continue  # unique-in-binary -> precision sozlesmesi
                fk = keys[0]
                if extracted_names.get(fk) is not None:
                    continue
                extracted_names[fk] = nm
                bp_assigned += 1
            if bp_assigned:
                stats["elf_boilerplate_recovered"] = bp_assigned
                logger.info(
                    "ELF boilerplate: %d fonksiyon kurtarildi", bp_assigned
                )
        except Exception as exc:  # pragma: no cover -- savunmaci
            logger.debug("ELF boilerplate kurtarma hatasi: %s", exc)

    def _apply_manual_overrides(
        self, extracted_names: dict, context: "PipelineContext", stats: dict
    ) -> dict:
        """Analistin elle verdigi isimleri (kalici override deposu) uygula.

        FIX-5 (2026-07-14). ``~/.karadul/overrides/<binary_hash>.json`` deposunda
        tutulan manuel fonksiyon isimleri MUTLAK oncelige sahiptir. Anahtar = ham
        ``FUN_xxxx`` Ghidra adresi; depo anahtari = ``context.target.file_hash``.

        IKI ASAMALI uygulama (reviewer MAJOR-1, 2026-07-14):
          1. ``extracted_names`` tohumlanir -> c_namer/merge'e guclu aday olur.
          2. Birlestirme SONRASI zorlama (P13a, AD-11 / B-C6): ad birlestirici
             (``_feedback_naming_merger.force_manual_names``) kunyedeki
             (``pre_name_meta``) elle adlari koda giden haritaya zorlar; tek basina
             (1) yeterli DEGIL (bindiff/refdiff ``.update()``'leri ve Bayesian merge
             manuel'i ezebilir). Metot uyguladigi map'i yine DONDURUR (test ve
             kunye icin); asama kodu bu donus degerini okumaz.

        Diger FIX metotlarindan farki: ``static_dir`` yerine ``context`` alir --
        decompiled dizine muhtac degil, yalnizca binary hash'e ihtiyac var.
        Opsiyonel ikinci kaynak: config'te ``overrides_path`` set edilmisse o
        JSON dosyasi da yuklenip uygulanir (auto-discover bozulmaz).
        """
        manual_map: dict[str, str] = {}
        try:
            if not isinstance(extracted_names, dict):
                return manual_map
            bh = getattr(getattr(context, "target", None), "file_hash", "") or ""
            from karadul.core import overrides

            # GUVENLIK (reviewer 2026-07-14): all_names() ve acik --overrides
            # yolu READ tarafinda dogrulama YAPMIYOR (dogrulama yalnizca set_name
            # WRITE'inda). El-editli/bozuk/dis kaynakli bir JSON'daki addr/name
            # dogrudan extracted_names -> naming_map -> AhoReplacer (kaynak yeniden
            # yazma) ve model.names'e sizabilir. Her giriseyi WRITE ile ayni
            # kanonik dogrulayicidan gecir; gecmeyeni SESSIZCE atla (ana hatti
            # dusurme). Gecerli override'lari asla reddetmez -- yalnizca kirli veriyi.
            def _valid_override(_addr: object, _name: object) -> bool:
                try:
                    overrides._validate_addr(_addr)   # FUN_/DAT_<hex> veya sembol
                    overrides._validate_name(_name)   # C tanimlayicisi
                    return True
                except Exception:
                    return False

            applied = 0
            rejected = 0

            # 1) Auto-discover: hash'ten ~/.karadul/overrides/<hash>.json
            if bh:
                for addr, name in overrides.all_names(bh).items():
                    if name and _valid_override(addr, name):
                        extracted_names[addr] = name  # tohum -- asama 1
                        manual_map[addr] = name        # merge sonrasi zorlama -- asama 2
                        applied += 1
                    elif name:
                        rejected += 1

            # 2) Opsiyonel acik yol (CLI --overrides / config.overrides_path).
            #    Auto-discover'a EK bir kaynak; ayni addr icin bu da ezebilir.
            ov_path = None
            try:
                ov_path = getattr(
                    getattr(getattr(context, "config", None), "binary_reconstruction", None),
                    "overrides_path",
                    None,
                )
            except Exception:
                ov_path = None
            if ov_path:
                try:
                    _data = json.loads(Path(ov_path).read_text(encoding="utf-8"))
                    _ov = _data.get("overrides", {}) if isinstance(_data, dict) else {}
                    for addr, rec in _ov.items():
                        nm = rec.get("name") if isinstance(rec, dict) else rec
                        if nm and _valid_override(addr, nm):
                            extracted_names[addr] = nm  # tohum -- asama 1
                            manual_map[addr] = nm        # merge sonrasi zorlama -- asama 2
                            applied += 1
                        elif nm:
                            rejected += 1
                except Exception as exc:
                    # bozuk/eksik acik dosya ana hatti dusurmesin -- ama sessiz kalma
                    logger.debug("Acik override dosyasi okunamadi (%s): %s", ov_path, exc)

            if rejected:
                logger.warning(
                    "Manuel override: %d gecersiz giris atlandi (addr/name dogrulamasi)",
                    rejected,
                )
            if applied:
                stats["manual_overrides_applied"] = applied
                logger.info("Manuel override: %d isim uygulandi", applied)
        except Exception as exc:
            # override deposu sorunlari asla ana hatti dusurmesin -- ama iz birak;
            # yoksa YENI ozellik sessizce no-op olur (import/API kirilirsa fark edilmez).
            logger.debug("Manuel override uygulanamadi: %s", exc)
        return manual_map

    def _runner_failure(
        self, start: float, phase: str, exc: BaseException,
        errors: list[str], stats: dict, artifacts: dict,
    ) -> StageResult:
        """Adım koşucusu düştü: aşama başarısız + dürüst durum (P14 notu, P-S4 kalem 5).

        Eskiden üç ``except RuntimeError`` dalı ``reconstruct_status`` yazmıyordu
        (rapor ve arayüz durumu ``finalize``'dan bekliyor; düşen koşuda alan hiç
        yoktu). Sözlük ``core.pipeline`` ile aynı (``basarisiz``).
        """
        from karadul.core.pipeline import OUTCOME_FAILED

        reason = f"{phase} adım koşucusu düştü: {exc}"
        out_stats = dict(stats)
        out_stats["reconstruct_status"] = OUTCOME_FAILED
        out_stats["reconstruct_failure_reasons"] = [reason]
        out_stats["partial"] = False
        return StageResult(
            stage_name=self.name,
            success=False,
            duration_seconds=time.monotonic() - start,
            errors=list(errors) + [str(exc)],
            stats=out_stats,
            artifacts=dict(artifacts),
        )

    def _execute_binary(self, context: PipelineContext, start: float) -> StageResult:
        """Binary reconstruction — decompile edilmis C'yi okunabilir yap.

        Tek yol: üç adım koşucusu (``karadul.pipeline``). Faz 1 ve Faz 2'nin
        (feedback_loop, computation_struct_recovery, struct_recovery) yapıtları
        Faz 3 koşucusuna (inline_detection … finalize) tohum olarak geçer;
        ``finalize`` StageResult'ı döndürür. Eski tek gövdeli yol (``_load_binary``,
        ``_run_*`` metotları, sıfır turluk döngü) 2026-11-18'de silindi (K-3 A1, P-S2).
        """
        rc = ReconstructionContext(start=start, stage_name=self.name)
        self._prepare_workspace(context, rc)

        errors: list[str] = rc.errors
        artifacts: dict[str, Path] = rc.artifacts
        stats: dict = rc.stats

        # mypy narrowing: _prepare_workspace bu alanlari set eder, None olamaz.
        assert rc.static_dir is not None, "_prepare_workspace static_dir set etmedi"
        assert rc.reconstructed_dir is not None, "_prepare_workspace reconstructed_dir set etmedi"
        static_dir: Path = rc.static_dir

        _use_step_registry = bool(
            getattr(context.config, "pipeline", None)
            and context.config.pipeline.use_step_registry
        )
        if not _use_step_registry:
            # use_step_registry=False yolu yok: eski monolit (Faz 1 dalı, sıfır turluk
            # döngü, Faz 3 yedeği) 2026-07-18 ve 2026-11-18'de (K-3 A1, P-S2) silindi.
            # Config/YAML hâlâ False verebilir (test_yaml_override); Ghidra'dan ÖNCE
            # yüksek sesle uyarıp tek yol olan adım koşucusuyla sürdürüyoruz.
            logger.warning(
                "use_step_registry=False artik desteklenmiyor (Phase 3 inline "
                "monolith 2026-07-18'de kaldirildi); step-registry yoluna "
                "geciliyor. Config/YAML override'inizi kaldirabilirsiniz.",
            )
        # Plan v2.2 N1 adım 3: KS-1 bağlaması ve ön ad künyesi. Step yolu doldurur;
        # None iken tohum eskisi gibi çalışır.
        _ks1_binding: Any = None
        _pre_name_meta: dict | None = None
        from karadul.pipeline.runner import PipelineRunner
        from karadul.pipeline.steps.kesin_anchors import (
            seed_inputs as _ks1_seed_inputs,
            with_pre_name_meta as _with_pre_name_meta,
        )
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
                # Plan v2.2 N1 adım 3: KS-1 kesin çapaları (static/'ten bir kez
                # çıkarılır; bayrak kapalıyken iş yapmaz). Adları aşağıdaki tohum yazar.
                "kesin_anchors",
                # v1.11.0 Hafta 1: BSim SHADOW MODE — ghidra_metadata
                # sonrasi (bsim_matches.json resolve edilebilsin),
                # byte_pattern oncesi. Fusion'a/NameMerger'a YAZMAZ,
                # sadece bsim_shadow.json dump eder.
                "bsim_match",
                "byte_pattern",
                # v1.13 Dalga 1: anti-debug + packer fingerprint.
                # binary_prep sonrasi (binary_for_byte_match resolve edildi),
                # pcode_cfg_analysis oncesi. Yalnizca ham binary'i okurlar,
                # sonraki adimlara ekstra artifact (anti_debug_findings,
                # packer_fingerprints) ureterek static/ altinda yazarlar.
                "anti_debug",
                "packer_fingerprint",
                # v1.15-B/C/D (2026-05-10): graceful-skip step'ler
                # (PE-only PDB, Linux ELF TRex, lisansli BinaryNinja)
                "pdb_symbol_recovery",
                "trex_struct_recovery",
                "binaryninja_analysis",
                # P-ÜV6a: üst veri üreticileri (Go pclntab, ObjC yöntem listesi). Bayrak
                # kapalıyken iş yapmaz (durum `kapali`); adlar Faz 2 ad kanallarına gider.
                "go_metadata_recovery",
                "objc_metadata_recovery",
                # P-ÜV6b: Swift tip üst verisi ve C++ RTTI üreticileri (bayrak kapalıyken iş
                # yapmaz; Swift adları Faz 2 ad kanalına, RTTI bağları kanıt satırına gider).
                "swift_metadata_recovery",
                "rtti_recovery",
                # B7 (2026-05-13): type recovery JSON tüketici
                "type_recovery_consumer",
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
            return self._runner_failure(start, "Faz 1", exc, errors, stats, artifacts)

        # Faz 1 yapıtlarından aşağıda okunanlar (yalnız silinen eski yolun okuduğu
        # köprü adları — c_files, file_cache, pcode_json … — 2026-11-18'de kalktı).
        _a = step_ctx.artifacts
        decompiled_dir = _a["decompiled_dir"]
        # ghidra_metadata — JSON path'leri
        functions_json = _a["functions_json_path"]
        strings_json = _a["strings_json_path"]
        call_graph_json = _a["call_graph_json_path"]
        xrefs_json = _a["xrefs_json_path"]
        # ghidra_metadata — parse cache + signature DB
        _func_data = _a["functions_data"]
        _string_data = _a["strings_data"]
        _call_graph_data = _a["call_graph_data"]
        sig_matches = _a["sig_matches"]
        # algorithm_id + parallel_algo_eng -> confidence_filter bunlari
        # filtered artifact olarak tekrar expose eder.
        algo_result = _a["algo_result_filtered"]
        eng_result = _a["eng_result_filtered"]
        extracted_names = _a["extracted_names"]
        _capa_capabilities = _a["capa_capabilities"]
        # kesin_anchors: bağlama ve ön ad künyesi (adım kapalıysa ikisi de None)
        _ks1_binding, _pre_name_meta = _ks1_seed_inputs(_a.get("kesin_anchors"))

        # stats/errors/artifacts merge — step'lerin biriktirdigi.
        # v1.14.0 Dalga 0: artifacts_pending mirror'i kaldirildi;
        # produce_artifact() ile yazilan stage artifact'lar dogrudan
        # step_ctx.stage_artifacts'tan okunuyor.
        stats.update(step_ctx.stats)
        errors.extend(step_ctx.errors)
        _stage_pending = dict(step_ctx.stage_artifacts)
        if _stage_pending:
            artifacts.update(_stage_pending)

        # v1.9.2: naming_result init (dir() anti-pattern fix)
        naming_result = None

        # KOK SEBEP FIX (2026-07-16): main/gnulib/boilerplate/override
        # tohumunu Phase-2 feedback_loop naming step'inden ONCE extracted_names'e
        # enjekte et. feedback_loop step'i pre_names'i buradan (seed_artifacts ->
        # a["extracted_names"]) okur; tohum eksikse c_namer FUN_xxx'i davranissal
        # sablonla (version_output_version, memory_exhausted) yeniden adlandirir
        # ve main/gnulib bir daha kurtarilamaz (AhoReplacer FUN_xxx literalini
        # kaybeder). extracted_names, _a["extracted_names"] ile ayni dict objesi;
        # yerinde mutasyon seed'e yansir. Idempotent -> ortak koddaki tekrar no-op.
        if isinstance(extracted_names, dict):
            self._seed_recovery_pre_names(
                extracted_names, static_dir, context, stats,
                kesin=_ks1_binding, meta=_pre_name_meta,
            )

        # v1.10.0 M1 T3.4: Phase 2 — feedback_loop + struct_recovery
        # Phase 1 artifact'larini seed olarak gecir (naming_result dahil
        # degil cunku feedback_loop uretir). feedback_loop step'inin
        # needs listesi Phase 1'den gelen her seyi kapsiyor.
        try:
            # v1.10.0 M4: computation_struct_recovery struct_recovery'den ONCE
            # calisir; MaxSMT adaylarini struct_recovery adimi motora iletir
            # (P10, BORU-04). CFG-iso / fuzyon / yapi kurtarma YALNIZ adimlarda
            # kosar: asama kodundaki ikinci kopya ("ESKI monolith entegrasyon"
            # blogu, BORU-01) 2026-11-18'de silindi (K-3 A1b, P-S2).
            runner_phase2 = PipelineRunner(steps=[
                "feedback_loop",
                "computation_struct_recovery",
                "struct_recovery",
            ])
            # Künye c_namer'a bu tohumla ulaşır (ctx.artifacts["pre_name_meta"]).
            step_ctx2 = runner_phase2.run(
                context,
                seed_artifacts=_with_pre_name_meta(step_ctx.artifacts, _pre_name_meta),
            )
        except RuntimeError as exc:
            return self._runner_failure(start, "Faz 2", exc, errors, stats, artifacts)

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
        # Faz 3'teki finalize yakınsama nedenini kendi koşucusunun yapıtlarından okur;
        # feedback_loop'un çıktısı bu koşucuda kalır, Faz 3 tohumuna buradan taşınır.
        _convergence_reason = _b.get("convergence_reason")

        # stats/errors/pending artifact merge
        # v1.14.0 Dalga 0: artifacts_pending mirror'i kaldirildi;
        # Phase 2 step'lerinin produce_artifact'i step_ctx2.stage_artifacts'a
        # yaziliyor.
        stats.update(step_ctx2.stats)
        errors.extend(step_ctx2.errors)
        _stage_pending2 = dict(step_ctx2.stage_artifacts)
        if _stage_pending2:
            artifacts.update(_stage_pending2)

        # P-S4 (2026-11-19): Faz 2'den sonraki ikinci ``_seed_recovery_pre_names``
        # çağrısı kaldırıldı. Tohum yalnız Faz 2'den ÖNCE (yukarıda) koşar; ikinci
        # çağrının mutasyona uğrattığı ``extracted_names``'i Faz 3 okumuyordu, dönüş
        # değeri (elle ad haritası) okunmuyordu ve elle adı birleştirmeden sonra
        # zorlayan iş P13a'dan beri ad birleştiricide (``force_manual_names``).

        # v1.10.0 M1 T3.5: Phase 3 — step registry runner2. 10 post-feedback
        # step'i calistir (inline_detection ... finalize). Finalize step'i
        # StageResult'i dondurur; biz stats/errors/artifacts'i merge edip
        # donuyoruz.

        # Faz 1 / Faz 2'nin urettigi degiskenleri Phase 3 step'lerine seed olarak
        # aktar. Phase 3 runner'i bunlarin uzerine ek artifact yazar.
        _seed: dict[str, Any] = {
            "decompiled_dir": decompiled_dir,
            # inline_detection feedback_loop/struct_recovery sonrasi nihai
            # decompiled dizini "final_decompiled_dir" key'i altinda bekler
            # (inline_detection.py:31, v1.10.0 H5+H6). Buradaki local
            # `decompiled_dir` zaten struct_recovery_decompiled_dir'e (yoksa
            # final_decompiled_dir'e) cozumlenmis nihai dizin; ayni degeri
            # bu key altinda da sunmazsak Phase 3 runner'i eksik-girdi ile
            # patlar (use_step_registry=True regresyonu).
            "final_decompiled_dir": decompiled_dir,
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
        # finalize, stats["convergence_reason"]'ı bu tohumdan yazar (yoksa "unknown").
        if _convergence_reason is not None:
            _seed["convergence_reason"] = _convergence_reason
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
            return self._runner_failure(start, "Faz 3", exc, errors, stats, artifacts)

        # Phase 3 artifact'lari + shim'e yazilanlar birlikte topla.
        _stage_result: StageResult = step_ctx3.artifacts["stage_result"]
        # Phase 1/2 stats ve errors'i finalize'in ciktisiyla birlestir.
        _stage_result.stats = {**stats, **_stage_result.stats}
        _stage_result.errors = errors + _stage_result.errors
        _stage_result.artifacts = {**artifacts, **_stage_result.artifacts}
        _finalize_binary_outcome(_stage_result, naming_result, context.config)
        return _stage_result

    # BICIM-02: deobfuscate aşamasının sonucu yoksa (ör. `--stage reconstruct`)
    # derin hattın adım dosyaları bu sırayla aday olur. Girdinin kopyaları
    # (00_original*), parça dizinleri (stream_chunks/, deep_chunks/) ve modül
    # dizini (webpack_modules/) hiçbir koşulda ana kaynak olmaz.
    _JS_STEP_OUTPUTS: tuple[str, ...] = (
        "03_enhanced_renamed.js",
        "02_deep_deobfuscated.js",
        "01b_synchrony.js",
        "01_beautified.js",
    )

    @classmethod
    def _select_js_source(
        cls, context: PipelineContext, deob_dir: Path,
    ) -> tuple[Path | None, dict[str, Any]]:
        """JS yeniden kurmanın ana kaynağını seç ve seçimi kayda yaz (BICIM-02).

        Öncelik: deobfuscate aşamasının ``artifacts["output_file"]``'ı (derin hattın
        "son başarılı adımın dosyası"; girdinin kopyası asla). Aşama koştu ama çıktı
        üretmediyse kaynak YOK: özgün kod "yeniden kurulmuş" diye sunulmaz. Aşama
        sonucu hiç yoksa adım dosyaları ``_JS_STEP_OUTPUTS`` sırasıyla; derin adım
        girdinin dönüştürülmemiş kopyasıysa (``deep_deob_fallback_copy``) atlanır.

        Dönüş: (kaynak ya da None, stats'a yazılacak alanlar). Alanlar:
        ``source_selection`` (deobfuscate_output / adim_dosyasi / yok),
        ``deobfuscation_status`` (ok / partial / failed / atlandi / basarisiz /
        sonuc_yok), gerekçe ve gerekiyorsa uyarı.
        """
        info: dict[str, Any] = {}
        deob = (getattr(context, "results", None) or {}).get("deobfuscate")
        fallback_copy = False
        if deob is not None:
            dstats = deob.stats or {}
            fallback_copy = bool(dstats.get("deep_deob_fallback_copy"))
            if deob.skipped:
                info["deobfuscation_status"] = "atlandi"
            else:
                info["deobfuscation_status"] = dstats.get(
                    "status", "ok" if deob.success else "basarisiz",
                )
            out = (deob.artifacts or {}).get("output_file")
            out_path = Path(out) if out else None
            if out_path is not None and out_path.is_file():
                info["source_selection"] = "deobfuscate_output"
                if info["deobfuscation_status"] != "ok":
                    info["source_warning"] = (
                        f"Deobfuscation durumu '{info['deobfuscation_status']}': yeniden "
                        f"kurma deobfuscation zincirinin son başarılı adımının çıktısı "
                        f"({out_path.name}) üstünde; derin dönüşüm "
                        + ("uygulanmadı." if not deob.success else "kısmi.")
                    )
                return out_path, info
            info["source_selection"] = "yok"
            reason = dstats.get("skip_reason") or "; ".join(
                str(e) for e in (deob.errors or [])[:2]
            )
            info["source_selection_reason"] = (
                "Deobfuscation aşaması kaynak üretmedi"
                + (f" ({reason})" if reason else "")
                + "; özgün girdi yeniden kurulmuş kod diye sunulmaz."
            )
            return None, info

        info["deobfuscation_status"] = "sonuc_yok"
        for name in cls._JS_STEP_OUTPUTS:
            if name == "02_deep_deobfuscated.js" and fallback_copy:
                continue
            cand = deob_dir / name
            if cand.is_file() and cand.stat().st_size > 0:
                info["source_selection"] = "adim_dosyasi"
                info["source_warning"] = (
                    "Deobfuscate aşamasının sonucu bu koşuda yok; kaynak adım "
                    f"dosyasından seçildi ({name})."
                )
                return cand, info
        info["source_selection"] = "yok"
        info["source_selection_reason"] = (
            "Deobfuscate edilmiş dosya bulunamadı (deobfuscated/ altında adım çıktısı yok)."
        )
        return None, info

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

        # BICIM-02: kaynak = deobfuscation zincirinin GERÇEK çıktısı (eskiden
        # deobfuscated/ altındaki EN BÜYÜK .js; derin dönüşüm kodu küçülttüğünde
        # özgün ya da yalnız güzelleştirilmiş dosya seçiliyordu).
        main_source, source_info = self._select_js_source(context, deob_dir)
        stats.update(source_info)
        if main_source is None:
            reason = source_info.get("source_selection_reason", "")
            return StageResult(
                stage_name=self.name,
                success=False,
                skipped=True,
                duration_seconds=time.monotonic() - start,
                stats={**stats, "skip_reason": reason},
            )
        stats["source_file"] = main_source.name
        stats["source_size"] = main_source.stat().st_size
        if source_info.get("source_warning"):
            errors.append(source_info["source_warning"])

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
                # P20 / BICIM-03: yukarıdaki üç kova UYGULANAN adlar (toplam ==
                # variables_renamed); analizcinin eşik öncesi adayları ayrı.
                stats["rename_candidates_high"] = naming_result.candidates_high
                stats["rename_candidates_medium"] = naming_result.candidates_medium
                stats["rename_candidates_low"] = naming_result.candidates_low
                errors.extend(naming_result.errors)
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
                except Exception as exc:
                    logger.warning(
                        "Context naming fallback basarisiz: %s",
                        exc, exc_info=True,
                    )
                    errors.append(f"Context naming fallback: {exc}")
        except Exception as exc:
            logger.warning("Context naming hatasi: %s", exc)
            errors.append(f"Context naming hatasi: {exc}")
            current_file = main_source

        # NOT (2026-05-13): LLM-Assisted Variable Naming kaldirildi.
        # Berke kalici karari: feedback_no_llm.md — deterministic, CPU-only.

        context.report_progress("Step 3/7: Parameter Recovery", 0.25)
        # 1.8. Param Recovery (this.X=param, call-site, destructuring)
        #      ContextNamer degisken isimlerini verdi, simdi fonksiyon
        #      parametrelerini de kurtariyoruz. 5 strateji ile LLM-siz
        #      parametre ismi recovery.
        from karadul.reconstruction.param_recovery import ParamRecovery
        param_recovery = ParamRecovery(context.config)

        try:
            param_result = param_recovery.recover(current_file)
            if (
                param_result.success
                and param_result.recovered > 0
                and param_result.recovery_json is not None
            ):
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
        # BICIM-13: derin hat (smart-webpack-unpack.mjs) modülleri
        # webpack_modules/modules/ altına yazar; eskiden bir üst dizine bakılıyor,
        # ModuleSplitter ve ProjectReconstructor hiçbir koşuda çalışmıyordu.
        webpack_dir = deob_dir / "webpack_modules" / "modules"
        split_result = None

        if webpack_dir.is_dir() and any(webpack_dir.glob("*.js")):
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
                    # BICIM-13: reconstruct-project.mjs her yazdığı modülü
                    # ayrıştırıcıyla sınar; ayrıştırılamayan adıyla bildirilir.
                    script = recon_result.stats.get("reconstruct_script") or {}
                    if "modules_parse_ok" in script:
                        stats["project_modules_parse_ok"] = script["modules_parse_ok"]
                        stats["project_modules_parse_failed"] = script["modules_parse_failed"]
                        if script["modules_parse_failed"]:
                            errors.append(
                                "ProjectReconstructor: "
                                f"{script['modules_parse_failed']} modül dosyası "
                                "ayrıştırılamıyor: "
                                + ", ".join(
                                    f.get("file", "?")
                                    for f in script.get("parse_failed_files", [])[:5]
                                )
                            )
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
                    # P20 / BICIM-12: giriş = ad/tip/yorum adımlarının son çıktısı
                    named_source=current_file,
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
    requires: tuple[str, ...] = ("identify",)  # static opsiyonel -- basarisiz olsa bile rapor uretilmeli

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
            json_path = JSONReporter(config=context.config).generate(pipeline_result, context.workspace)
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
                    func_caps: list[str] = name_to_caps[func_name]
                    # Onceki satir zaten /** ... */ ise, mevcut blogun sonuna ekle
                    # Yoksa yeni blok olustur
                    cap_lines = [f" * @capability {cap}" for cap in func_caps]
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
