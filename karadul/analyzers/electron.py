"""
Electron App Analyzer — macOS .app bundle'lari icin analiz ve deobfuscation.

Electron uygulamalarinin icindeki ASAR arsivini extract edip JS dosyalarini
analiz eder. JavaScriptAnalyzer ve DeobfuscationManager ile entegre calisir.

Calisma akisi:
1. .app bundle icinde app.asar'i bul
2. npx asar extract ile ASAR'i coz
3. Extract edilen JS dosyalarini JavaScriptAnalyzer ile analiz et
4. Deobfuscation zincirini ana JS dosyalari uzerinde calistir
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from karadul.analyzers import register_analyzer
from karadul.analyzers.base import BaseAnalyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.subprocess_runner import SubprocessRunner
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.deobfuscators.manager import DeobfuscationManager

logger = logging.getLogger(__name__)

# ASAR icindeki ana JS dosya aday isimleri (buyukten kucuge oncelik)
_MAIN_JS_CANDIDATES = (
    "dist/cli.js",
    "dist/main.js",
    "dist/index.js",
    "app/main.js",
    "app/index.js",
    "src/main.js",
    "src/index.js",
    "main.js",
    "index.js",
    "cli.js",
    "app.js",
    "bundle.js",
    "electron.js",
)


@register_analyzer(TargetType.ELECTRON_APP)
class ElectronAnalyzer(BaseAnalyzer):
    """Electron .app bundle analyzer.

    macOS .app dizininden ASAR arsivini bulur, extract eder ve
    icindeki JavaScript dosyalarini analiz eder.

    Attributes:
        supported_types: Sadece ELECTRON_APP.
    """

    supported_types = [TargetType.ELECTRON_APP]

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._runner = SubprocessRunner(config)
        self._deob_manager = DeobfuscationManager(config)

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Electron uygulamasinin statik analizi.

        1. .app bundle'dan app.asar konumunu bul
        2. ASAR'i extract et
        3. Extract edilen dizindeki JS dosyalarini bul
        4. Her JS dosyasi icin temel istatistikleri topla
        5. Sonuclari birlestir

        Args:
            target: Electron uygulama bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Statik analiz sonucu.
        """
        start = time.monotonic()
        errors: list[str] = []
        artifacts: dict[str, Path] = {}
        stats: dict[str, object] = {}

        # 1. ASAR'i bul
        asar_path = self._find_asar(target.path)
        if asar_path is None:
            # ASAR yoksa unpacked app/ dizinini kontrol et
            app_dir = self._find_unpacked_app(target.path)
            if app_dir is None:
                errors.append(
                    f"app.asar veya app/ dizini bulunamadi: {target.path}"
                )
                return StageResult(
                    stage_name="static",
                    success=False,
                    duration_seconds=time.monotonic() - start,
                    errors=errors,
                )
            extract_dir = app_dir
            stats["asar_extracted"] = False
            stats["app_dir"] = str(app_dir)
        else:
            stats["asar_path"] = str(asar_path)
            stats["asar_size"] = asar_path.stat().st_size

            # 2. ASAR'i extract et
            extract_dir = workspace.get_stage_dir("raw") / "asar_extracted"
            extract_success = self._extract_asar(asar_path, extract_dir)

            if not extract_success:
                errors.append(f"ASAR extract basarisiz: {asar_path}")
                return StageResult(
                    stage_name="static",
                    success=False,
                    duration_seconds=time.monotonic() - start,
                    errors=errors,
                )

            stats["asar_extracted"] = True
            artifacts["asar_extracted_dir"] = extract_dir

        # 3. JS dosyalarini bul
        js_files = self._find_js_files(extract_dir)
        stats["js_file_count"] = len(js_files)
        stats["total_js_size"] = sum(f.stat().st_size for f in js_files)

        if not js_files:
            errors.append("Extract edilen dizinde JS dosyasi bulunamadi")
            return StageResult(
                stage_name="static",
                success=False,
                duration_seconds=time.monotonic() - start,
                artifacts=artifacts,
                stats=stats,
                errors=errors,
            )

        # 4. JS dosyalarinin istatistiklerini topla
        js_file_info = []
        main_js = self._find_main_js(extract_dir, js_files)
        stats["main_js"] = str(main_js) if main_js else None

        for js_file in js_files:
            rel_path = js_file.relative_to(extract_dir)
            file_info = {
                "path": str(rel_path),
                "size": js_file.stat().st_size,
                "is_main": js_file == main_js,
            }
            # Buyuk dosyalarin ilk satirini oku (bundler tespiti icin)
            try:
                with open(js_file, "r", encoding="utf-8", errors="replace") as f:
                    head = f.read(1024)
                    file_info["has_webpack"] = "__webpack_require__" in head
                    file_info["has_module_exports"] = "module.exports" in head
                    file_info["line_count"] = head.count("\n") + 1
            except OSError:
                file_info["has_webpack"] = False
                file_info["has_module_exports"] = False
                file_info["line_count"] = 0

            js_file_info.append(file_info)
            artifacts[f"js_{rel_path}"] = js_file

        # Istatistikleri kaydet
        stats["js_files"] = js_file_info
        stats["webpack_bundles"] = sum(
            1 for f in js_file_info if f.get("has_webpack", False)
        )

        # 5. JSON artifact olarak kaydet
        workspace.save_json("static", "electron-analysis", {
            "target": target.name,
            "stats": stats,
            "errors": errors,
        })

        duration = time.monotonic() - start
        logger.info(
            "Electron statik analiz: %d JS dosyasi, %d webpack bundle, "
            "toplam %d bytes (%.1fs)",
            len(js_files),
            stats.get("webpack_bundles", 0),
            stats.get("total_js_size", 0),
            duration,
        )

        return StageResult(
            stage_name="static",
            success=True,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Extract edilmis JS dosyalari uzerinde deobfuscation.

        Ana JS dosyasi (en buyuk veya bilinen entry point)
        uzerinde DeobfuscationManager.run_chain() calistirir.

        Args:
            target: Electron uygulama bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Deobfuscation sonucu.
        """
        start = time.monotonic()
        errors: list[str] = []
        artifacts: dict[str, Path] = {}
        stats: dict[str, object] = {}

        # Extract edilmis dizini bul
        extract_dir = workspace.get_stage_dir("raw") / "asar_extracted"
        if not extract_dir.exists():
            # Belki ASAR extract edilmemis, dogrudan app/ dizini kullanilmis
            extract_dir_alt = self._find_unpacked_app(target.path)
            if extract_dir_alt is None:
                errors.append(
                    "ASAR extract dizini bulunamadi. "
                    "Once analyze_static calistirilmali."
                )
                return StageResult(
                    stage_name="deobfuscate",
                    success=False,
                    duration_seconds=time.monotonic() - start,
                    errors=errors,
                )
            extract_dir = extract_dir_alt

        # JS dosyalarini bul
        js_files = self._find_js_files(extract_dir)
        if not js_files:
            errors.append("Deobfuscation icin JS dosyasi bulunamadi")
            return StageResult(
                stage_name="deobfuscate",
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=errors,
            )

        # Ana JS dosyasini bul
        main_js = self._find_main_js(extract_dir, js_files)
        target_js = main_js or max(js_files, key=lambda f: f.stat().st_size)

        logger.info(
            "Electron deobfuscation hedefi: %s (%d bytes)",
            target_js.name,
            target_js.stat().st_size,
        )

        # DeobfuscationManager ile chain calistir
        deob_result = self._deob_manager.run_chain(target_js, workspace)

        stats["deob_steps_completed"] = deob_result.steps_completed
        stats["deob_steps_failed"] = deob_result.steps_failed
        stats["deob_steps_skipped"] = deob_result.steps_skipped
        stats["deob_stats"] = deob_result.stats

        if deob_result.output_file:
            artifacts["deobfuscated_main"] = deob_result.output_file

        if not deob_result.success:
            errors.append(
                f"Deobfuscation basarisiz: "
                f"failed={deob_result.steps_failed}"
            )

        duration = time.monotonic() - start

        return StageResult(
            stage_name="deobfuscate",
            success=deob_result.success,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def _find_asar(self, app_path: Path) -> Path | None:
        """app.asar konumunu bul.

        Aranacak konumlar (sirasyla):
        1. Contents/Resources/app.asar
        2. Resources/app.asar
        3. app.asar (dogrudan verildiyse)

        Args:
            app_path: .app bundle veya dosya yolu.

        Returns:
            app.asar yolu veya None.
        """
        # .asar dosyasi dogrudan verildiyse
        if app_path.suffix == ".asar" and app_path.is_file():
            return app_path

        # .app bundle icinde
        candidates = [
            app_path / "Contents" / "Resources" / "app.asar",
            app_path / "Resources" / "app.asar",
        ]

        for candidate in candidates:
            if candidate.exists():
                logger.debug("ASAR bulundu: %s", candidate)
                return candidate

        # TargetInfo metadata'sindan
        # (TargetDetector _detect_app_bundle'da asar yolunu kaydeder)
        # Bu metod dogrudan app_path uzerinde calisir

        logger.debug("app.asar bulunamadi: %s", app_path)
        return None

    def _find_unpacked_app(self, app_path: Path) -> Path | None:
        """Unpacked app dizinini bul (ASAR yerine).

        Bazi Electron uygulamalari ASAR kullanmaz,
        dogrudan Resources/app/ dizininde JS dosyalarini barindirir.

        Args:
            app_path: .app bundle yolu.

        Returns:
            app/ dizin yolu veya None.
        """
        candidates = [
            app_path / "Contents" / "Resources" / "app",
            app_path / "Resources" / "app",
        ]

        for candidate in candidates:
            if candidate.exists() and candidate.is_dir():
                logger.debug("Unpacked app dizini bulundu: %s", candidate)
                return candidate

        return None

    def _extract_asar(self, asar_path: Path, output_dir: Path) -> bool:
        """ASAR arsivini extract et.

        ``npx asar extract <asar> <output>`` komutunu calistirir.
        npx yerine ``npx --yes`` kullanilarak package otomatik yuklenir.

        Args:
            asar_path: ASAR dosya yolu.
            output_dir: Extract edilecek dizin.

        Returns:
            Basarili ise True.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # npx asar extract
        npm_path = str(self.config.tools.npm)
        # npx binary'si npm'in yaninda olmali
        npx_path = str(Path(npm_path).parent / "npx") if npm_path != "npm" else "npx"

        cmd = [
            npx_path, "--yes", "@electron/asar",
            "extract", str(asar_path), str(output_dir),
        ]

        logger.info(
            "ASAR extract baslatiliyor: %s -> %s",
            asar_path.name, output_dir,
        )

        result = self._runner.run_command(cmd, timeout=self.config.timeouts.subprocess)

        if not result.success:
            logger.error(
                "ASAR extract basarisiz (code=%d): %s",
                result.returncode,
                result.stderr[:500],
            )
            return False

        # Extract edilen dosya sayisini kontrol et
        extracted_files = list(output_dir.rglob("*"))
        file_count = sum(1 for f in extracted_files if f.is_file())

        if file_count == 0:
            logger.error("ASAR extract sonrasi dosya bulunamadi: %s", output_dir)
            return False

        logger.info(
            "ASAR extract basarili: %d dosya cikarildi", file_count,
        )
        return True

    def _find_js_files(
        self,
        directory: Path,
        min_size: int | None = None,
    ) -> list[Path]:
        """Dizindeki JS dosyalarini bul.

        node_modules/ ve test/ dizinlerini atlar.
        Config'deki webpack_module_min_size'dan kucuk dosyalari filtreler.

        Args:
            directory: Aranacak dizin.
            min_size: Minimum dosya boyutu (byte). None ise config'den al.

        Returns:
            JS dosya yollarinin listesi (buyukten kucuge siralanmis).
        """
        effective_min_size = min_size or self.config.analysis.webpack_module_min_size

        # Atlanacak dizinler
        skip_dirs = {"node_modules", ".git", "__pycache__", "test", "tests", "spec"}

        js_files: list[Path] = []
        for js_path in directory.rglob("*.js"):
            # Skip dirs kontrolu
            parts = js_path.relative_to(directory).parts
            if any(part in skip_dirs for part in parts):
                continue

            # Minimum boyut kontrolu
            try:
                if js_path.stat().st_size < effective_min_size:
                    continue
            except OSError:
                continue

            js_files.append(js_path)

        # .mjs dosyalarini da ekle
        for mjs_path in directory.rglob("*.mjs"):
            parts = mjs_path.relative_to(directory).parts
            if any(part in skip_dirs for part in parts):
                continue
            try:
                if mjs_path.stat().st_size < effective_min_size:
                    continue
            except OSError:
                continue
            js_files.append(mjs_path)

        # Boyuta gore sirala (buyukten kucuge)
        js_files.sort(key=lambda f: f.stat().st_size, reverse=True)
        return js_files

    def _find_main_js(
        self,
        extract_dir: Path,
        js_files: list[Path],
    ) -> Path | None:
        """Ana JS dosyasini bul.

        1. Bilinen isim adaylarina bakar (_MAIN_JS_CANDIDATES)
        2. package.json'dan "main" field'ini okur
        3. En buyuk JS dosyasini dondurur

        Args:
            extract_dir: Extract edilmis dizin.
            js_files: Bulunan JS dosyalari.

        Returns:
            Ana JS dosyasi veya None.
        """
        if not js_files:
            return None

        # 1. package.json'dan main field'ini oku
        pkg_json_path = extract_dir / "package.json"
        if pkg_json_path.exists():
            import json
            try:
                with open(pkg_json_path, "r", encoding="utf-8") as f:
                    pkg = json.load(f)
                main_entry = pkg.get("main", "")
                if main_entry:
                    main_path = extract_dir / main_entry
                    if main_path.exists() and main_path.suffix in (".js", ".mjs", ".cjs"):
                        logger.debug("package.json main: %s", main_entry)
                        return main_path
            except (json.JSONDecodeError, OSError):
                pass

        # 2. Bilinen isim adaylari
        for candidate in _MAIN_JS_CANDIDATES:
            candidate_path = extract_dir / candidate
            if candidate_path.exists():
                logger.debug("Bilinen isim adayi: %s", candidate)
                return candidate_path

        # 3. En buyuk JS dosyasi
        return js_files[0] if js_files else None
