"""
JavaScript Bundle Analyzer — JS dosyalari icin statik analiz ve deobfuscation.

Babel AST analiz, js-beautify ve webpack unpack islemlerini
Node.js scriptleri uzerinden SubprocessRunner ile calistirir.
"""

from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path

from karadul.analyzers import register_analyzer
from karadul.analyzers.base import BaseAnalyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.subprocess_runner import SubprocessRunner
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)


@register_analyzer(TargetType.JS_BUNDLE)
class JavaScriptAnalyzer(BaseAnalyzer):
    """JavaScript bundle analiz ve deobfuscation.

    Node.js scriptlerini SubprocessRunner uzerinden cagirarak:
    - Babel AST ile fonksiyon/string/import/export cikarir
    - js-beautify ile kod formatlar
    - Webpack bundle'i modullere ayirir

    Scripts dizini Config.scripts_dir'den alinir.
    """

    supported_types = [TargetType.JS_BUNDLE]

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._runner = SubprocessRunner(config)
        self._scripts_dir = config.scripts_dir

    # Buyuk dosya esik degeri (MB) -- bu degerden buyuk dosyalar icin
    # stream-parse.mjs ile chunk'lanarak analiz edilir
    LARGE_FILE_THRESHOLD_MB = 100

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Babel AST ile statik analiz.

        1. Dosyayi workspace/raw/'a kopyalar
        2. 100MB+ dosyalar icin stream-parse.mjs ile chunk'lar
        3. scripts/deobfuscate.mjs'i SubprocessRunner ile calistirir
        4. JSON sonuclari parse eder
        5. workspace/static/'e artifact olarak kaydeder
        6. StageResult dondurur

        Args:
            target: JS dosya bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Analiz sonucu (stats, artifacts, errors).
        """
        start = time.monotonic()
        errors: list[str] = []
        artifacts: dict[str, Path] = {}
        stats: dict[str, object] = {}

        # 1. Dosyayi workspace/raw/'a kopyala
        raw_dir = workspace.get_stage_dir("raw")
        raw_copy = raw_dir / target.path.name
        try:
            shutil.copy2(target.path, raw_copy)
            artifacts["raw_copy"] = raw_copy
        except OSError as exc:
            errors.append(f"Dosya kopyalanamadi: {exc}")
            return StageResult(
                stage_name="static",
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=errors,
            )

        # Buyuk dosya kontrolu -- 100MB+ icin stream-parse ile chunk'la,
        # sonra en kucuk chunk'i analiz et (tum dosyayi Babel ile parse
        # etmek memory patlatir)
        file_size_mb = target.file_size / (1024 * 1024)
        analysis_file = raw_copy

        if file_size_mb >= self.LARGE_FILE_THRESHOLD_MB:
            logger.info(
                "Buyuk dosya (%.0f MB), chunk bazli analiz uygulanacak", file_size_mb,
            )
            stats["large_file_mode"] = True
            # ChunkedProcessor ile ilk 50MB'lik bolumu cikar
            try:
                from karadul.core.chunked_processor import ChunkedProcessor
                chunker = ChunkedProcessor(self.config, max_chunk_mb=50)
                chunk_dir = raw_dir / "analysis_chunks"
                split_result = chunker.split_js_file(raw_copy, chunk_dir)
                if split_result.success and split_result.chunks:
                    # Ilk chunk'i analiz dosyasi olarak kullan
                    analysis_file = split_result.chunks[0].path
                    stats["analysis_chunk"] = split_result.chunks[0].path.name
                    stats["total_chunks_for_analysis"] = len(split_result.chunks)
            except Exception as exc:
                logger.warning("Chunk olusturulamadi, tum dosya denenecek: %s", exc)

        # 2. deobfuscate.mjs'i calistir
        deobfuscate_script = self._scripts_dir / "deobfuscate.mjs"
        try:
            # Buyuk dosyalar icin artirilmis timeout ve heap
            effective_timeout = self.config.timeouts.babel_parse
            extra_env = None
            if file_size_mb >= self.LARGE_FILE_THRESHOLD_MB:
                effective_timeout = max(effective_timeout, 300)
                extra_env = {"NODE_OPTIONS": "--max-old-space-size=8192"}

            cmd = [
                str(self.config.tools.node),
                "--max-old-space-size=8192",
                str(deobfuscate_script),
                str(analysis_file),
            ]

            sub_result = self._runner.run_command(
                cmd,
                timeout=effective_timeout,
                cwd=self._scripts_dir,
                env=extra_env,
            )

            if not sub_result.success:
                raise RuntimeError(
                    f"deobfuscate.mjs basarisiz (code={sub_result.returncode}): "
                    f"{sub_result.stderr[:500]}"
                )

            result_json = sub_result.parsed_json
            if result_json is None:
                raise RuntimeError(
                    f"deobfuscate.mjs JSON ciktisi uretemedi: {sub_result.stdout[:500]}"
                )

        except FileNotFoundError as exc:
            errors.append(f"Script bulunamadi: {exc}")
            return StageResult(
                stage_name="static",
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=errors,
            )
        except RuntimeError as exc:
            errors.append(f"Babel analiz hatasi: {exc}")
            return StageResult(
                stage_name="static",
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=errors,
            )

        # 3. JSON sonuclari isle
        if not result_json.get("success", False):
            script_errors = result_json.get("errors", [])
            errors.extend(script_errors)
            # Kismi sonuc varsa devam et
            if not result_json.get("stats"):
                return StageResult(
                    stage_name="static",
                    success=False,
                    duration_seconds=time.monotonic() - start,
                    errors=errors,
                )

        # Stats
        stats = result_json.get("stats", {})

        # Script'ten gelen hatalari ekle
        if result_json.get("errors"):
            errors.extend(result_json["errors"])

        # 4. Artifact'leri kaydet
        static_dir = workspace.get_stage_dir("static")

        # Tam AST analiz sonucu
        ast_path = workspace.save_json("static", "ast-analysis", result_json)
        artifacts["ast_analysis"] = ast_path

        # Fonksiyon listesi
        functions = result_json.get("functions", [])
        if functions:
            func_path = workspace.save_json("static", "functions", {"functions": functions})
            artifacts["functions"] = func_path

        # String listesi
        strings = result_json.get("strings", [])
        if strings:
            str_path = workspace.save_json("static", "strings", {"strings": strings})
            artifacts["strings"] = str_path

        # Import/export listesi
        imports = result_json.get("imports", [])
        exports = result_json.get("exports", [])
        if imports or exports:
            ie_path = workspace.save_json("static", "imports-exports", {
                "imports": imports,
                "exports": exports,
            })
            artifacts["imports_exports"] = ie_path

        # Webpack module ID'leri
        webpack_modules = result_json.get("webpack_modules", [])
        if webpack_modules:
            wp_path = workspace.save_json("static", "webpack-modules", {
                "module_ids": webpack_modules,
                "count": len(webpack_modules),
            })
            artifacts["webpack_modules"] = wp_path

        duration = time.monotonic() - start
        # Hatalar olsa bile kismi sonuc varsa success=True
        success = bool(stats) and (len(functions) > 0 or len(strings) > 0)

        logger.info(
            "JS statik analiz: %d fonksiyon, %d string, %d import, %d export, %d webpack module",
            stats.get("functions", 0),
            stats.get("strings", 0),
            stats.get("imports", 0),
            stats.get("exports", 0),
            stats.get("webpack_modules", 0),
        )

        return StageResult(
            stage_name="static",
            success=success,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Beautify + webpack unpack deobfuscation.

        1. scripts/beautify.mjs ile dosyayi beautify eder
        2. Webpack bundle tespit edilmisse scripts/unpack-webpack.mjs ile modullere ayirir
        3. Sonuclari workspace/deobfuscated/'e kaydeder

        Args:
            target: JS dosya bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Deobfuscation sonucu.
        """
        start = time.monotonic()
        errors: list[str] = []
        artifacts: dict[str, Path] = {}
        stats: dict[str, object] = {}

        deob_dir = workspace.get_stage_dir("deobfuscated")

        # Kaynak dosya: raw copy varsa onu kullan, yoksa orijinal
        raw_copy = workspace.get_stage_dir("raw") / target.path.name
        source_file = raw_copy if raw_copy.exists() else target.path

        # 1. Beautify
        beautified_path = deob_dir / f"{target.path.stem}.beautified.js"
        beautify_script = self._scripts_dir / "beautify.mjs"

        beautify_success = False
        try:
            beautify_result = self._runner.run_node_script(
                script_path=beautify_script,
                args=[str(source_file), str(beautified_path)],
                timeout=self.config.timeouts.subprocess,
                cwd=self._scripts_dir,
            )

            if beautify_result.get("success", False):
                beautify_success = True
                artifacts["beautified"] = beautified_path
                beautify_stats = beautify_result.get("stats", {})
                stats["beautify"] = beautify_stats
                logger.info(
                    "Beautify: %d -> %d satir (%.1fx genisleme)",
                    beautify_stats.get("input_lines", 0),
                    beautify_stats.get("output_lines", 0),
                    beautify_stats.get("expansion_ratio", 0),
                )
            else:
                errors.append(f"Beautify basarisiz: {beautify_result.get('errors', [])}")

        except (FileNotFoundError, RuntimeError) as exc:
            errors.append(f"Beautify hatasi: {exc}")

        # 2. Webpack unpack -- sadece webpack bundle tespit edilmisse
        is_webpack = self._is_webpack_bundle(target, workspace)
        webpack_success = False

        if is_webpack:
            webpack_output_dir = deob_dir / "webpack_modules"
            unpack_script = self._scripts_dir / "unpack-webpack.mjs"

            try:
                unpack_result = self._runner.run_node_script(
                    script_path=unpack_script,
                    args=[str(source_file), str(webpack_output_dir)],
                    timeout=self.config.timeouts.subprocess,
                    cwd=self._scripts_dir,
                )

                if unpack_result.get("success", False):
                    webpack_success = True
                    artifacts["webpack_modules_dir"] = webpack_output_dir
                    unpack_stats = unpack_result.get("stats", {})
                    stats["webpack_unpack"] = unpack_stats
                    # Modul dosyalarini artifact olarak kaydet
                    module_list = unpack_result.get("modules", [])
                    for mod in module_list:
                        mod_path = webpack_output_dir / mod["file"]
                        if mod_path.exists():
                            artifacts[f"webpack_module_{mod['id']}"] = mod_path
                    logger.info(
                        "Webpack unpack: %d/%d modul yazildi",
                        unpack_stats.get("modules_written", 0),
                        unpack_stats.get("modules_found", 0),
                    )
                else:
                    errors.append(f"Webpack unpack basarisiz: {unpack_result.get('errors', [])}")

            except (FileNotFoundError, RuntimeError) as exc:
                errors.append(f"Webpack unpack hatasi: {exc}")

        duration = time.monotonic() - start
        success = beautify_success or webpack_success

        return StageResult(
            stage_name="deobfuscate",
            success=success,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def _is_webpack_bundle(self, target: TargetInfo, workspace: Workspace) -> bool:
        """Hedefin webpack bundle olup olmadigini kontrol et.

        Kaynaklari:
        1. TargetDetector'in metadata'sindaki bundler bilgisi
        2. Statik analiz sonucundaki webpack_modules sayisi

        Returns:
            True ise webpack bundle.
        """
        # Metadata'dan bundler kontrolu
        if target.metadata.get("bundler") == "webpack":
            return True

        # Statik analiz sonucundan webpack module sayisi kontrolu
        wp_data = workspace.load_json("static", "webpack-modules")
        if wp_data and wp_data.get("count", 0) > 0:
            return True

        # AST analizinden webpack_modules kontrolu
        ast_data = workspace.load_json("static", "ast-analysis")
        if ast_data and ast_data.get("stats", {}).get("webpack_modules", 0) > 0:
            return True

        return False
