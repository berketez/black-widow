"""Gelismis deobfuscation pipeline.

deep-deobfuscate.mjs ve smart-webpack-unpack.mjs'i orkestre eder.
Standart DeobfuscationManager'in alternatifi -- cok daha agresif.

Zincir:
  1. beautify (js-beautify ile format)
  2. deep-deobfuscate.mjs (10 phase Babel transform incl. semantic rename)
  2.5. cursor-enhanced-rename.mjs (25 ek context-aware rename kurali, LLM gerektirmez)
  3. smart-webpack-unpack.mjs (modul ayirma)
  4. Her modul uzerinde tekrar deep-deobfuscate (variable renaming)

Sonuç sözleşmesi (dürüst başarı, 2026-09-25):
  ``success`` yalnız hattın ASIL çıktısı -- deep-deobfuscate dönüşümü (chunked
  modda: en az bir bloğu dönüştürülmüş birleşik dosya) -- gerçekten üretildiğinde
  True olur. Eskiden ``any(adım başarılı)`` idi: beautify'ın (ya da hata sonrası
  yaptığı kopyanın) "başarısı" tüm hattı başarılı sayıyordu.
  ``stats["status"]``: "ok" | "partial" | "failed"; ``stats["warnings"]``: kullanıcıya
  gösterilecek kısa açıklamalar. İkisi de stats'ta çünkü DeobfuscationStage
  StageResult'a yalnız stats'ı aktarır. Adım bazında durum ``steps[ad]["success"]``;
  uygulanamayan adım ``"skipped": True`` (hata değil, durumu bozmaz).
"""

from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..core.subprocess_runner import SubprocessRunner
from ..core.workspace import Workspace

logger = logging.getLogger(__name__)

# Genel durum (stats["status"]).
STATUS_OK = "ok"            # asıl çıktı üretildi, başarısız/eksik adım yok
STATUS_PARTIAL = "partial"  # asıl çıktı üretildi ama en az bir adım başarısız/eksik
STATUS_FAILED = "failed"    # asıl çıktı üretilmedi


@dataclass
class DeepDeobfuscationResult:
    """Deep deobfuscation sonucu.

    Attributes:
        success: Hattın asıl çıktısı (deep-deobfuscate dönüşümü) gerçekten
            üretildi mi. Yardımcı bir adımın (beautify, enhanced rename, modül
            ayırma) başarısı tek başına yetmez.
        steps: Her adımın durumu: ``{"success": bool, "skipped"?: bool,
            "partial"?: bool, "error"?: str, ...}``. ``skipped`` = adım
            uygulanamadı/istenmedi (hata değil); ``partial`` = adım çıktı üretti
            ama işin bir kısmı başarısız (ör. bazı modüller/bloklar).
        output_file: Başarılı bir adımın ürettiği en son dosya; hiçbir adım
            dosya üretmediyse None. Girdinin kopyaları (00_original, script'in
            fallback kopyası) asla output_file sayılmaz.
        modules_dir: Ayrilmis modullerin dizini.
        total_modules: Cikarilan modul sayisi.
        bundle_format: Tespit edilen bundle formati.
        stats: Detayli istatistikler; ``status`` ve ``warnings`` burada.
        duration_seconds: Toplam sure.
    """
    success: bool = False
    steps: dict[str, dict[str, Any]] = field(default_factory=dict)
    output_file: Path | None = None
    modules_dir: Path | None = None
    total_modules: int = 0
    bundle_format: str = "unknown"
    stats: dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0

    @property
    def status(self) -> str:
        """"ok" | "partial" | "failed" (tek kaynak: stats["status"])."""
        return self.stats.get("status", STATUS_OK if self.success else STATUS_FAILED)

    @property
    def warnings(self) -> list[str]:
        """Kullanıcıya gösterilecek uyarılar (tek kaynak: stats["warnings"])."""
        return list(self.stats.get("warnings", []))

    def summary(self) -> str:
        completed = sum(1 for s in self.steps.values() if s.get("success"))
        skipped = sum(
            1 for s in self.steps.values() if not s.get("success") and s.get("skipped")
        )
        failed = len(self.steps) - completed - skipped
        label = {STATUS_OK: "OK", STATUS_PARTIAL: "PARTIAL"}.get(self.status, "FAIL")
        return (
            f"[{label}] Deep deob: "
            f"{completed} done, {failed} fail, {skipped} skipped, "
            f"{self.total_modules} modules, "
            f"{self.duration_seconds:.1f}s"
        )


class DeepDeobfuscationPipeline:
    """Gelismis deobfuscation -- deep-deobfuscate.mjs ve smart-webpack-unpack.mjs orkestrasyon.

    Mevcut DeobfuscationManager'dan farki:
    - 10 phase Babel transform (constant folding, dead code, comma split, semantic rename, vb.)
    - esbuild/webpack akilli modul cikarma
    - Her modul uzerinde ikinci pass variable renaming

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._runner = SubprocessRunner(config)
        self._scripts_dir = config.scripts_dir

    # Buyuk dosya esik degeri (MB) -- bu degerden buyuk dosyalar chunk'lanir
    LARGE_FILE_THRESHOLD_MB = 100
    # İkinci geçiş (modül bazlı rename) bundan büyük modülleri atlar.
    MODULE_RENAME_MAX_BYTES = 500_000
    # Chunked modda bundan küçük bloklar deobfuscate edilmez, olduğu gibi korunur.
    CHUNK_MIN_BYTES = 100

    def run(
        self,
        input_file: Path,
        workspace: Workspace,
        *,
        skip_beautify: bool = False,
        phases: str = "all",
    ) -> DeepDeobfuscationResult:
        """Tam deep deobfuscation pipeline.

        200MB+ dosyalar icin otomatik olarak streaming/chunked isleme kullanir:
        stream-parse.mjs ile dosyayi block'lara ayirir, her block'u bagimsiz isle.

        Args:
            input_file: Obfuscated JS dosyasi.
            workspace: Calisma dizini.
            skip_beautify: Beautify adimini atla (zaten beautified ise).
            phases: deep-deobfuscate phase'leri ("all" veya "1,2,3,...").

        Returns:
            DeepDeobfuscationResult.
        """
        start = time.monotonic()
        result = DeepDeobfuscationResult()

        if not input_file.exists():
            result.steps["init"] = {"success": False, "error": f"Dosya yok: {input_file}"}
            return self._finalize(result, main_output=None, start=start)

        # Buyuk dosya kontrolu -- 100MB+ ise stream-parse ile chunk'la
        file_size_mb = input_file.stat().st_size / (1024 * 1024)
        if file_size_mb >= self.LARGE_FILE_THRESHOLD_MB:
            logger.info(
                "Buyuk dosya tespit edildi (%.0f MB), stream-parse kullaniliyor",
                file_size_mb,
            )
            return self._run_chunked(input_file, workspace, skip_beautify, phases, start)

        deob_dir = workspace.get_stage_dir("deobfuscated")

        # Orijinal dosyayi kopyala
        original = deob_dir / f"00_original{input_file.suffix}"
        shutil.copy2(input_file, original)
        result.stats["original_size"] = input_file.stat().st_size
        current = original  # zincirin sıradaki adımının girdisi
        produced: Path | None = None  # başarılı bir adımın ürettiği son dosya
        main_output: Path | None = None  # asıl çıktı (deep-deobfuscate dönüşümü)

        # --- Adim 1: Beautify ---
        if not skip_beautify:
            beautified = deob_dir / "01_beautified.js"
            step_result = self._step_beautify(current, beautified)
            result.steps["beautify"] = step_result
            if step_result["success"] and beautified.exists():
                current = produced = beautified
                result.stats["beautified_size"] = beautified.stat().st_size
            # Başarısızsa orijinalle devam edilir. Eskiden girdi "01_beautified.js"
            # adıyla kopyalanıp adım başarılı sayılıyordu (sahte başarı).
        else:
            result.steps["beautify"] = {
                "success": False, "skipped": True,
                "reason": "skip_beautify=True: çağıran beautify'ı atladı",
            }

        # --- Adim 2: Deep Deobfuscate (10 phase) ---
        deep_output = deob_dir / "02_deep_deobfuscated.js"
        step_result = self._step_deep_deobfuscate(current, deep_output, phases)
        result.steps["deep_deobfuscate"] = step_result
        if step_result["success"] and deep_output.exists():
            current = produced = main_output = deep_output
            result.stats["deep_deob_size"] = deep_output.stat().st_size
            result.stats["phases_completed"] = step_result.get("phases_completed", [])
        elif deep_output.exists() and deep_output.stat().st_size > 0:
            # Parse basarisiz: script kaynagi DONUSTURMEDEN 02_...'e kopyaladi
            # (fallback_copy). Zincir bu kopyayla surer (icerik girdiyle ayni),
            # ama bu dosya asla asil cikti / output_file sayilmaz.
            current = deep_output
            result.stats["deep_deob_fallback_copy"] = True
            logger.info("Deep deob basarisiz ama output dosyasi mevcut (fallback), devam ediliyor")

        # --- Adim 2.5: Enhanced Semantic Rename (cursor-enhanced-rename.mjs) ---
        enhanced_script = self._scripts_dir / "cursor-enhanced-rename.mjs"
        if enhanced_script.exists() and current.exists():
            enhanced_output = deob_dir / "03_enhanced_renamed.js"
            step_result = self._step_enhanced_rename(current, enhanced_output)
            result.steps["enhanced_rename"] = step_result
            if step_result.get("success") and enhanced_output.exists():
                current = produced = enhanced_output
                result.stats["enhanced_renamed"] = step_result.get("renamed", 0)
        else:
            logger.debug("Enhanced rename script bulunamadi, atlaniyor")

        # --- Adim 3: Smart Webpack Unpack ---
        modules_out = deob_dir / "webpack_modules"
        step_result = self._step_smart_unpack(current, modules_out)
        result.steps["smart_unpack"] = step_result
        if step_result["success"]:
            result.modules_dir = modules_out
            result.total_modules = step_result.get("total_modules", 0)
            result.bundle_format = step_result.get("bundle_format", "unknown")
            result.stats["unpack_modules"] = result.total_modules

        # --- Adim 4: Her modul uzerinde ikinci pass (variable renaming only) ---
        if result.modules_dir and result.total_modules > 0:
            rename_result = self._step_rename_modules(result.modules_dir)
            result.steps["module_rename"] = rename_result
            result.stats["modules_renamed"] = rename_result.get("renamed_count", 0)

        # Sonuc -- basari yalniz asil cikti uretildiyse (eskiden any(adim basarili))
        result.output_file = produced
        return self._finalize(result, main_output=main_output, start=start)

    def _finalize(
        self,
        result: DeepDeobfuscationResult,
        *,
        main_output: Path | None,
        start: float,
    ) -> DeepDeobfuscationResult:
        """Genel başarıyı, durumu ve uyarıları adımlardan dürüstçe hesapla.

        - success: yalnız asıl çıktı (``main_output``) üretildiyse True.
        - status: asıl çıktı yoksa "failed"; varken başarısız ya da kısmi
          (``partial``) bir adım varsa "partial"; yoksa "ok". ``skipped`` adımlar
          (uygulanamadı/istenmedi) durumu bozmaz.
        - warnings: her başarısız/kısmi adım için bir satır + asıl çıktı yoksa
          bunu açıkça söyleyen satır.
        """
        warnings: list[str] = []
        if main_output is None:
            warnings.append(
                "Asıl çıktı üretilmedi: deep-deobfuscate dönüşümü başarısız. "
                "Başarılı görünen yardımcı adımlar (beautify vb.) deobfuscation sayılmaz."
            )
        degraded = False
        for name, info in result.steps.items():
            if info.get("success"):
                if info.get("partial"):
                    degraded = True
                    warnings.append(f"{name} kısmi: {self._step_reason(info)}")
                continue
            if info.get("skipped"):
                continue
            degraded = True
            warnings.append(f"{name} başarısız: {self._step_reason(info)}")

        if main_output is None:
            status = STATUS_FAILED
        elif degraded:
            status = STATUS_PARTIAL
        else:
            status = STATUS_OK
        result.success = main_output is not None
        result.stats["status"] = status
        result.stats["warnings"] = warnings
        result.duration_seconds = time.monotonic() - start

        if status == STATUS_OK:
            logger.info("Deep deobfuscation: %s", result.summary())
        else:
            logger.warning(
                "Deep deobfuscation %s: %s -- %s",
                "KISMİ" if status == STATUS_PARTIAL else "BAŞARISIZ",
                result.summary(), " | ".join(warnings),
            )
        return result

    @staticmethod
    def _step_reason(info: dict) -> str:
        """Adım sözlüğünden kısa gerekçe: önce ``error``, yoksa ilk ``errors`` öğesi."""
        if info.get("error"):
            return str(info["error"])
        errs = info.get("errors")
        if isinstance(errs, list) and errs:
            return str(errs[0])
        return "ayrıntı yok"

    def _step_beautify(self, input_file: Path, output_file: Path) -> dict:
        """js-beautify ile format.

        Başarısızlıkta girdi KOPYALANMAZ ve adım başarılı sayılmaz (eskiden
        girdi 01_beautified.js adıyla kopyalanıp success=True dönülüyordu).
        run_node_script yerine run_command: beautify.mjs hata nedenini stdout
        JSON'unda verir, stderr boştur; gerekçe kaybolmasın.
        """
        script = self._scripts_dir / "beautify.mjs"
        if not script.exists():
            return {"success": False, "error": f"Script yok: {script}"}

        start = time.monotonic()
        try:
            sub_result = self._runner.run_command(
                [str(self._config.tools.node), str(script),
                 str(input_file), str(output_file)],
                timeout=self._config.timeouts.subprocess,
            )
        except Exception as exc:
            logger.warning("Beautify hata: %s", exc)
            return {
                "success": False,
                "error": f"{type(exc).__name__}: {exc}",
                "duration": time.monotonic() - start,
            }

        json_result = sub_result.parsed_json or {}
        produced = output_file.exists() and output_file.stat().st_size > 0
        if sub_result.success and json_result.get("success") and produced:
            return {
                "success": True,
                "duration": time.monotonic() - start,
                "stats": json_result.get("stats", {}),
            }

        script_errors = json_result.get("errors")
        if isinstance(script_errors, list) and script_errors:
            reason = "; ".join(str(e) for e in script_errors)
        elif json_result.get("success"):
            reason = "başarı bildirdi ama çıktı dosyası yok/boş"
        else:
            reason = (sub_result.stderr or "").strip()[:300] or f"code={sub_result.returncode}"
        logger.warning("Beautify basarisiz, orijinalle devam: %s", reason)
        return {
            "success": False,
            "error": f"beautify.mjs başarısız: {reason}",
            "duration": time.monotonic() - start,
        }

    def _step_deep_deobfuscate(
        self, input_file: Path, output_file: Path, phases: str,
    ) -> dict:
        """deep-deobfuscate.mjs ile 10 phase transform (incl. semantic rename)."""
        script = self._scripts_dir / "deep-deobfuscate.mjs"
        if not script.exists():
            return {"success": False, "error": f"Script yok: {script}"}

        start = time.monotonic()
        try:
            # 9MB+ dosya icin buyuk heap
            node_args = [
                "--max-old-space-size=8192",
                str(script),
                str(input_file),
                str(output_file),
                "--phases", phases,
            ]

            # Timeout: dosya boyutuna gore hesapla
            # Phase 10 (semantic rename) cok agir -- 15MB dosya ~10 dakika surebilir
            # Kural: 100 saniye/MB, minimum 300s, maksimum 1800s (30 dk)
            file_size_mb = input_file.stat().st_size / (1024 * 1024)
            timeout_secs = max(300, min(1800, int(file_size_mb * 100)))
            logger.info(
                "Deep deobfuscate timeout: %ds (dosya: %.1f MB)",
                timeout_secs, file_size_mb,
            )

            sub_result = self._runner.run_command(
                [str(self._config.tools.node)] + node_args,
                timeout=timeout_secs,
            )

            if sub_result.parsed_json:
                json_result = sub_result.parsed_json
            else:
                return {
                    "success": False,
                    "error": "JSON parse edilemedi",
                    "stderr": sub_result.stderr[:500],
                    "duration": time.monotonic() - start,
                }

            # Başarı = script dönüşümü tamamladı VE çıktı gerçekten var. Script
            # ayrıştıramadığı girdide 0 ile çıkıp girdiyi kopyalar (fallback_copy,
            # success=false); bu asla başarı sayılmaz.
            reported = bool(json_result.get("success", False))
            success = (
                reported and output_file.exists() and output_file.stat().st_size > 0
            )
            step = {
                "success": success,
                "duration": time.monotonic() - start,
                "phases_completed": json_result.get("phases_completed", []),
                "stats": json_result.get("stats", {}),
                "errors": json_result.get("errors", []),
            }
            if not success:
                if reported:
                    step["error"] = (
                        "deep-deobfuscate.mjs başarı bildirdi ama çıktı dosyası yok/boş"
                    )
                elif json_result.get("fallback_copy"):
                    step["fallback_copy"] = True
                    step["error"] = (
                        "deep-deobfuscate.mjs girdiyi ayrıştıramadı; dönüşüm yapılmadı "
                        f"({output_file.name} girdinin dönüştürülmemiş kopyası)"
                    )
                else:
                    step["error"] = "deep-deobfuscate.mjs dönüşümü tamamlayamadı"
            return step
        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
                "duration": time.monotonic() - start,
            }

    def _step_enhanced_rename(self, input_file: Path, output_file: Path) -> dict:
        """cursor-enhanced-rename.mjs ile gelismis semantic rename.

        Phase 10'dan sonra kalan minified identifier'lari 25 ek kural ile
        context-aware rename eder. LLM kullanmaz.
        """
        script = self._scripts_dir / "cursor-enhanced-rename.mjs"
        if not script.exists():
            return {"success": False, "error": f"Script yok: {script}"}

        start = time.monotonic()
        try:
            file_size_mb = input_file.stat().st_size / (1024 * 1024)
            timeout_secs = max(120, min(600, int(file_size_mb * 50)))
            logger.info(
                "Enhanced rename timeout: %ds (dosya: %.1f MB)",
                timeout_secs, file_size_mb,
            )

            node_args = [
                "--max-old-space-size=8192",
                str(script),
                str(input_file),
                str(output_file),
            ]

            sub_result = self._runner.run_command(
                [str(self._config.tools.node)] + node_args,
                timeout=timeout_secs,
            )

            if sub_result.parsed_json:
                json_result = sub_result.parsed_json
                reported = bool(json_result.get("success", False))
                success = (
                    reported and output_file.exists() and output_file.stat().st_size > 0
                )
                step = {
                    "success": success,
                    "duration": time.monotonic() - start,
                    "renamed": json_result.get("renamed", 0),
                    "stats": json_result.get("stats", {}),
                    "errors": json_result.get("errors", []),
                }
                if not success:
                    step["error"] = (
                        "cursor-enhanced-rename.mjs başarı bildirdi ama çıktı dosyası yok/boş"
                        if reported else "cursor-enhanced-rename.mjs başarısız"
                    )
                return step
            return {
                "success": False,
                "error": "JSON parse edilemedi",
                "stderr": sub_result.stderr[:500] if sub_result.stderr else "",
                "duration": time.monotonic() - start,
            }
        except Exception as exc:
            logger.warning("Enhanced rename hata: %s", exc)
            return {
                "success": False,
                "error": str(exc),
                "duration": time.monotonic() - start,
            }

    def _step_smart_unpack(self, input_file: Path, output_dir: Path) -> dict:
        """smart-webpack-unpack.mjs ile modul cikarma."""
        script = self._scripts_dir / "smart-webpack-unpack.mjs"
        if not script.exists():
            return {"success": False, "error": f"Script yok: {script}"}

        output_dir.mkdir(parents=True, exist_ok=True)
        start = time.monotonic()

        try:
            node_args = [
                "--max-old-space-size=8192",
                str(script),
                str(input_file),
                str(output_dir),
            ]

            sub_result = self._runner.run_command(
                [str(self._config.tools.node)] + node_args,
                timeout=300,
            )

            if sub_result.parsed_json:
                json_result = sub_result.parsed_json
            else:
                return {
                    "success": False,
                    "error": "JSON parse edilemedi",
                    "stderr": sub_result.stderr[:500],
                    "duration": time.monotonic() - start,
                }

            step = {
                "success": bool(json_result.get("success", False)),
                "duration": time.monotonic() - start,
                "total_modules": json_result.get("total_modules", 0),
                "bundle_format": json_result.get("bundle_format", "unknown"),
                "helpers": json_result.get("helpers_detected", {}),
                "errors": json_result.get("errors", []),
            }
            if not step["success"]:
                if not step["total_modules"] and not step["errors"]:
                    # Script sorunsuz çalıştı, hata bildirmedi, modül bulamadı:
                    # girdi paket (bundle) değil. Hata değil, uygulanamaz.
                    step["skipped"] = True
                    step["reason"] = (
                        "Modül yapısı bulunamadı (webpack/esbuild paketi değil); "
                        "modül ayırma uygulanamaz"
                    )
                else:
                    step["error"] = "smart-webpack-unpack.mjs modül çıkaramadı"
            return step
        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
                "duration": time.monotonic() - start,
            }

    def _step_rename_modules(self, modules_dir: Path) -> dict:
        """Her modul dosyasi uzerinde variable renaming yap.

        Bir modül yalnız script dönüşümü başarıyla bitirdiyse (JSON success)
        yeniden adlandırılmış sayılır. deep-deobfuscate.mjs ayrıştıramadığı
        dosyada da 0 ile çıkıp girdiyi kopyalar; eskiden çıkış koduna bakıldığı
        için bu modüller "renamed" sayılıyor, adım da her koşulda success=True
        dönüyordu.
        """
        script = self._scripts_dir / "deep-deobfuscate.mjs"
        if not script.exists():
            return {"success": False, "error": f"Script yok: {script}"}

        # modules/ alt dizinindeki dosyalari isle
        actual_modules_dir = modules_dir / "modules"
        if not actual_modules_dir.exists():
            actual_modules_dir = modules_dir

        module_files = sorted(actual_modules_dir.glob("*.js"))
        if not module_files:
            # Çağrı yalnız unpack modül bildirdiğinde yapılır; dosya yoksa tutarsızlık.
            return {
                "success": False,
                "renamed_count": 0,
                "error": f"Unpack modül bildirdi ama modül dosyası yok: {actual_modules_dir}",
            }

        renamed_count = 0
        errors = []
        failed: list[str] = []
        first_failure = ""
        skipped_large = 0

        for mf in module_files:
            # Buyuk dosyalari atla
            if mf.stat().st_size > self.MODULE_RENAME_MAX_BYTES:
                skipped_large += 1
                continue

            try:
                tmp_output = mf.with_suffix(".renamed.js")
                node_args = [
                    "--max-old-space-size=4096",
                    str(script),
                    str(mf),
                    str(tmp_output),
                    "--phases", "9",  # Sadece variable renaming
                ]

                sub_result = self._runner.run_command(
                    [str(self._config.tools.node)] + node_args,
                    timeout=60,
                )

                if (
                    sub_result.success
                    and (sub_result.parsed_json or {}).get("success")
                    and tmp_output.exists()
                    and tmp_output.stat().st_size > 0
                ):
                    # Orijinalin uzerine yaz
                    shutil.move(str(tmp_output), str(mf))
                    renamed_count += 1
                else:
                    failed.append(mf.name)
                    if not first_failure:
                        script_errors = (sub_result.parsed_json or {}).get("errors") or []
                        first_failure = f"{mf.name}: " + (
                            str(script_errors[0]) if script_errors
                            else (sub_result.stderr or "").strip()[:200]
                            or f"code={sub_result.returncode}"
                        )
                    # Gecici dosyayi temizle
                    if tmp_output.exists():
                        tmp_output.unlink()
            except Exception as exc:
                errors.append(f"{mf.name}: {exc}")
                failed.append(mf.name)
                if not first_failure:
                    first_failure = f"{mf.name}: {type(exc).__name__}: {exc}"
                # Gecici dosya kaldiysa temizle
                tmp_out = mf.with_suffix(".renamed.js")
                if tmp_out.exists():
                    try:
                        tmp_out.unlink()
                    except OSError:
                        pass

        attempted = len(module_files) - skipped_large
        if attempted == 0:
            return {
                "success": False,
                "skipped": True,
                "reason": (
                    f"Tüm modüller boyut sınırını ({self.MODULE_RENAME_MAX_BYTES} bayt) "
                    "aşıyor; ikinci geçiş uygulanmadı"
                ),
                "renamed_count": 0,
                "total_files": len(module_files),
                "skipped_large": skipped_large,
            }

        step: dict[str, Any] = {
            "success": renamed_count > 0,
            "renamed_count": renamed_count,
            "total_files": len(module_files),
            "errors": errors,
        }
        if skipped_large:
            step["skipped_large"] = skipped_large
        if failed:
            step["failed_count"] = len(failed)
            step["failed_modules"] = failed[:20]
            step["error"] = (
                f"{len(failed)}/{attempted} modül yeniden adlandırılamadı "
                f"(ilk hata: {first_failure})"
            )
            if renamed_count:
                step["partial"] = True
        return step

    def _run_chunked(
        self,
        input_file: Path,
        workspace: Workspace,
        skip_beautify: bool,
        phases: str,
        start: float,
    ) -> DeepDeobfuscationResult:
        """Buyuk dosyalar icin stream-parse.mjs + chunk-bazli deobfuscation.

        200MB+ dosyalar icin:
        1. stream-parse.mjs ile dosyayi top-level block'lara ayir
        2. Her block'u bagimsiz deep-deobfuscate et
        3. Sonuclari birlestir

        Args:
            input_file: Buyuk JS dosyasi.
            workspace: Calisma dizini.
            skip_beautify: Beautify atlama flag'i.
            phases: deep-deobfuscate phase listesi.
            start: Baslangic zamani.

        Returns:
            DeepDeobfuscationResult.
        """
        result = DeepDeobfuscationResult()
        deob_dir = workspace.get_stage_dir("deobfuscated")

        # Orijinal dosyayi kopyala
        original = deob_dir / f"00_original{input_file.suffix}"
        shutil.copy2(input_file, original)
        result.stats["original_size"] = input_file.stat().st_size

        # Adim 1: stream-parse.mjs ile block'lara ayir
        chunks_dir = deob_dir / "stream_chunks"
        chunks_dir.mkdir(parents=True, exist_ok=True)

        stream_script = self._scripts_dir / "stream-parse.mjs"
        if not stream_script.exists():
            # Fallback: ChunkedProcessor ile Python tarafinda bol
            from ..core.chunked_processor import ChunkedProcessor
            chunker = ChunkedProcessor(self._config, max_chunk_mb=50)
            split_result = chunker.split_js_file(input_file, chunks_dir)
            if not split_result.success:
                result.steps["stream_parse"] = {
                    "success": False,
                    "error": "ChunkedProcessor da basarisiz",
                    "errors": split_result.errors,
                }
                return self._finalize(result, main_output=None, start=start)
            block_files = sorted(chunks_dir.glob("chunk_*.js"))
            result.steps["stream_parse"] = {
                "success": True,
                "method": "chunked_processor",
                "total_chunks": len(block_files),
                "total_lines": split_result.total_lines,
            }
        else:
            try:
                node_args = [
                    "--max-old-space-size=4096",
                    str(stream_script),
                    str(input_file),
                    str(chunks_dir),
                    "--max-block-kb", "512",
                ]
                sub_result = self._runner.run_command(
                    [str(self._config.tools.node)] + node_args,
                    timeout=600,  # 10 dakika (200MB+ icin)
                )

                if sub_result.parsed_json and sub_result.parsed_json.get("success"):
                    json_result = sub_result.parsed_json
                    result.steps["stream_parse"] = {
                        "success": True,
                        "method": "stream_parse_mjs",
                        "total_blocks": json_result.get("total_blocks", 0),
                        "total_lines": json_result.get("total_lines", 0),
                        "input_size_mb": json_result.get("input_size_mb", 0),
                    }
                else:
                    result.steps["stream_parse"] = {
                        "success": False,
                        "error": sub_result.stderr[:300] if sub_result.stderr else "unknown",
                    }
                    return self._finalize(result, main_output=None, start=start)
            except Exception as exc:
                result.steps["stream_parse"] = {
                    "success": False,
                    "error": str(exc),
                }
                return self._finalize(result, main_output=None, start=start)

            block_files = sorted(chunks_dir.glob("block_*.js"))

        if not block_files:
            # Blok yoksa bölme adımı işini yapmamıştır (eskiden success=True kalıyordu).
            result.steps["stream_parse"]["success"] = False
            result.steps["stream_parse"]["error"] = "Block dosyasi olusturulamadi"
            return self._finalize(result, main_output=None, start=start)

        logger.info("Stream parse: %d block olusturuldu", len(block_files))

        # Adim 2: Her block'u deep-deobfuscate et
        deep_chunks_dir = deob_dir / "deep_chunks"
        deep_chunks_dir.mkdir(parents=True, exist_ok=True)

        deep_script = self._scripts_dir / "deep-deobfuscate.mjs"
        deob_success = 0
        deob_errors = []
        attempted = 0
        skipped_small = 0

        for block_file in block_files:
            output_file = deep_chunks_dir / block_file.name
            # Kucuk block'lar deobfuscate edilmez ama birlesik ciktidan DUSURULMEZ:
            # eskiden atlaniyor, deep_chunks'a hic yazilmadigi icin birlesik
            # dosyada kayboluyordu (python_src olcumu: birlesik cikti 0 bayt).
            if block_file.stat().st_size < self.CHUNK_MIN_BYTES:
                shutil.copy2(block_file, output_file)
                skipped_small += 1
                continue

            attempted += 1
            try:
                node_args = [
                    "--max-old-space-size=8192",
                    str(deep_script),
                    str(block_file),
                    str(output_file),
                    "--phases", phases,
                ]
                sub = self._runner.run_command(
                    [str(self._config.tools.node)] + node_args,
                    timeout=120,  # Her block icin 2 dakika
                )
                # Script ayristiramadigi blokta da 0 ile cikip kopya yazar;
                # basari cikis kodundan degil JSON'dan okunur.
                if (
                    sub.success
                    and (sub.parsed_json or {}).get("success")
                    and output_file.exists()
                ):
                    deob_success += 1
                else:
                    # Orijinal block'u kopyala (deobfuscation basarisiz)
                    shutil.copy2(block_file, output_file)
            except Exception as exc:
                deob_errors.append(f"{block_file.name}: {exc}")
                shutil.copy2(block_file, output_file)

        chunks_step: dict[str, Any] = {
            "success": deob_success > 0,
            "total_chunks": len(block_files),
            "deob_success": deob_success,
            "errors": deob_errors[:10],
        }
        if skipped_small:
            chunks_step["skipped_small"] = skipped_small
        failed_chunks = attempted - deob_success
        if failed_chunks:
            chunks_step["failed_chunks"] = failed_chunks
            chunks_step["error"] = (
                f"{failed_chunks}/{attempted} blok deobfuscate edilemedi; "
                "bu bloklar birleşik çıktıda dönüştürülmemiş duruyor"
            )
            if deob_success:
                chunks_step["partial"] = True
        elif not attempted:
            chunks_step["error"] = (
                f"Deobfuscate edilecek boyutta blok yok (hepsi < {self.CHUNK_MIN_BYTES} bayt)"
            )
        result.steps["deep_deobfuscate_chunks"] = chunks_step

        # Adim 3: Birlestirilmis dosya olustur
        combined = deob_dir / "02_deep_deobfuscated.js"
        main_output: Path | None = None
        try:
            with open(combined, "w", encoding="utf-8") as out:
                for chunk_file in sorted(deep_chunks_dir.glob("*.js")):
                    content = chunk_file.read_text(encoding="utf-8", errors="replace")
                    out.write(content)
                    out.write("\n\n")
            result.stats["deep_deob_size"] = combined.stat().st_size
            # Hiçbir blok dönüştürülmediyse birleşik dosya yalnız orijinal
            # blokların toplamıdır: asıl çıktı / output_file sayılmaz.
            if deob_success:
                main_output = combined
                result.output_file = combined
        except OSError as exc:
            result.steps["combine"] = {"success": False, "error": str(exc)}

        # Adim 4: Smart webpack unpack (birlestirilmis dosya uzerinde)
        modules_out = deob_dir / "webpack_modules"
        step_result = self._step_smart_unpack(combined, modules_out)
        result.steps["smart_unpack"] = step_result
        if step_result.get("success"):
            result.modules_dir = modules_out
            result.total_modules = step_result.get("total_modules", 0)
            result.bundle_format = step_result.get("bundle_format", "unknown")
            result.stats["unpack_modules"] = result.total_modules

        # Adim 5: Her modul uzerinde ikinci pass (variable renaming)
        if result.modules_dir and result.total_modules > 0:
            rename_result = self._step_rename_modules(result.modules_dir)
            result.steps["module_rename"] = rename_result
            result.stats["modules_renamed"] = rename_result.get("renamed_count", 0)

        logger.info("Chunked deep deobfuscation: %d blocks", len(block_files))
        return self._finalize(result, main_output=main_output, start=start)
