"""
Electron App Analyzer — macOS .app bundle'lari icin analiz ve deobfuscation.

Electron uygulamalarinin icindeki ASAR arsivini extract edip JS dosyalarini
analiz eder. JavaScriptAnalyzer ve DeobfuscationManager ile entegre calisir.

Calisma akisi:
1. .app bundle icinde app.asar'i bul
2. ASAR'i Python'da ac (extract_asar; ag ve alt surec YOK)
3. Extract edilen JS dosyalarini JavaScriptAnalyzer ile analiz et
4. Deobfuscation zincirini ana JS dosyalari uzerinde calistir
"""

from __future__ import annotations

import json
import logging
import os
import stat
import struct
import time
import unicodedata
from pathlib import Path
from typing import Any

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


# ---------------------------------------------------------------------------
# ASAR açıcı (BICIM-06)
# ---------------------------------------------------------------------------
# Eskiden ASAR `npx --yes @electron/asar extract` ile açılıyordu: ağ kapalıyken
# bile npm kayıt deposundan sürümü sabitlenmemiş bir paket indirilip
# ÇALIŞTIRILIYORDU (tedarik zinciri riski; ağ yoksa Electron hattı düşüyordu).
# Biçim basit: Chromium Pickle.
#   [0:4]   u32 = 4                (ilk pickle'ın yük boyu)
#   [4:8]   u32 = header_size      (ikinci pickle'ın toplam boyu)
#   [8:12]  u32 = payload_size     (ikinci pickle'ın yük boyu)
#   [12:16] u32 = json_len         (JSON dizgisinin bayt boyu)
#   [16:16+json_len]  JSON başlık (UTF-8), 4 bayta hizalı dolgu
#   gövde = 8 + header_size'tan başlar; dosya ofsetleri gövdeye göredir.
# Girdi düşmandır: yol geçişi (`..`, `/`, mutlak yol), simgesel bağ, toplam
# boyut ve dosya sayısı bütçesi, harf duyarsız dosya sisteminde ad çakışması.
_ASAR_MAX_HEADER_BYTES = 64 * 1024 * 1024
_ASAR_MAX_FILES = 200_000
_ASAR_MAX_DEPTH = 256
_ASAR_MAX_NAME_BYTES = 255
_ASAR_COPY_CHUNK = 1024 * 1024


class AsarFormatError(ValueError):
    """ASAR başlığı geçersiz ya da güvenli biçimde okunamıyor."""


def _read_asar_header(fh: Any, file_size: int) -> tuple[dict[str, Any], int, int]:
    """(başlık JSON'u, gövde başlangıcı, başlık bayt boyu) döndür."""
    head = fh.read(16)
    if len(head) < 16:
        raise AsarFormatError("dosya ASAR başlığı için çok kısa")
    size_payload, header_size, payload_size, json_len = struct.unpack("<4I", head)
    if size_payload != 4:
        raise AsarFormatError(f"ASAR imzası yok (ilk alan {size_payload}, 4 beklenir)")
    if header_size > _ASAR_MAX_HEADER_BYTES:
        raise AsarFormatError(f"başlık çok büyük ({header_size} bayt)")
    if 8 + header_size > file_size:
        raise AsarFormatError("başlık dosya sonunu aşıyor")
    if payload_size + 4 > header_size or json_len + 4 > payload_size:
        raise AsarFormatError("başlık pickle boyutları tutarsız")
    raw = fh.read(json_len)
    if len(raw) != json_len:
        raise AsarFormatError("başlık JSON'u eksik")
    try:
        header = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise AsarFormatError(f"başlık JSON'u çözülemedi: {type(exc).__name__}") from exc
    if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
        raise AsarFormatError("başlıkta 'files' sözlüğü yok")
    return header, 8 + header_size, header_size


def _asar_name_ok(name: Any) -> bool:
    """Tek bileşenli, güvenli girdi adı mı?"""
    if not isinstance(name, str) or name in ("", ".", ".."):
        return False
    if "/" in name or "\\" in name or "\x00" in name:
        return False
    if len(name.encode("utf-8", "surrogatepass")) > _ASAR_MAX_NAME_BYTES:
        return False
    return True


def _copy_exact(src_fh: Any, dest: Path, size: int) -> None:
    """``src_fh``'nin bulunduğu yerden tam ``size`` baytı ``dest``'e yaz.

    Hedef simgesel bağ İZLENMEDEN açılır (O_NOFOLLOW); kaynak erken biterse
    OSError (yarım dosya bırakılmaz).
    """
    fd = os.open(
        str(dest),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    with os.fdopen(fd, "wb") as dfh:
        remaining = size
        while remaining > 0:
            chunk = src_fh.read(min(_ASAR_COPY_CHUNK, remaining))
            if not chunk:
                break
            dfh.write(chunk)
            remaining -= len(chunk)
    if remaining:
        dest.unlink(missing_ok=True)
        raise OSError(f"kaynak erken bitti ({remaining} bayt eksik)")


def extract_asar(
    asar_path: Path,
    output_dir: Path,
    *,
    max_total_bytes: int,
    max_files: int = _ASAR_MAX_FILES,
) -> dict[str, Any]:
    """ASAR arşivini ``output_dir`` altına Python'da aç (ağ ve alt süreç yok).

    ``<asar>.unpacked/`` altındaki "unpacked" girdiler oradan kopyalanır
    (yalnız kök içinde kalan, simgesel bağ olmayan düzenli dosyalar).
    Simgesel bağ girdileri (``link``) oluşturulmaz, sayılır.

    Returns:
        Rapor sözlüğü: yazılan dosya/dizin/bayt sayıları, atlanan girdiler
        (nedenine göre), yeniden adlandırılanlar, bütçe kesilmesi.

    Raises:
        AsarFormatError: Başlık geçersizse.
        OSError: Arşiv okunamazsa.
    """
    report: dict[str, Any] = {
        "format": "asar",
        "files_written": 0,
        "dirs_created": 0,
        "bytes_written": 0,
        "unpacked_files": 0,
        "skipped": {},
        "renamed": [],
        "truncated": False,
        "truncate_reason": None,
    }

    def skip(reason: str) -> None:
        report["skipped"][reason] = report["skipped"].get(reason, 0) + 1

    out_root = output_dir.resolve()
    unpacked_root = asar_path.parent / (asar_path.name + ".unpacked")
    unpacked_real = unpacked_root.resolve() if unpacked_root.is_dir() else None
    file_size = asar_path.stat().st_size

    with open(asar_path, "rb") as fh:
        header, body_start, header_size = _read_asar_header(fh, file_size)
        report["header_size"] = header_size
        total = 0
        written_entries = 0
        # (json düğümü, hedef dizin, arşiv içi göreli parçalar, derinlik)
        stack: list[tuple[dict[str, Any], Path, tuple[str, ...], int]] = [
            (header, out_root, (), 0),
        ]
        while stack:
            node, dest_dir, rel_parts, depth = stack.pop()
            files = node.get("files")
            if not isinstance(files, dict):
                skip("bad_directory")
                continue
            used: set[str] = set()
            for name in sorted(files):
                entry = files[name]
                if not _asar_name_ok(name) or not isinstance(entry, dict):
                    skip("bad_name")
                    continue
                if written_entries >= max_files:
                    report["truncated"] = True
                    report["truncate_reason"] = f"dosya sayısı bütçesi ({max_files})"
                    return report
                key = unicodedata.normalize("NFC", name).casefold()
                out_name = name
                if key in used:
                    k = 2
                    while f"{key}~{k}" in used:
                        k += 1
                    out_name = f"{name}~{k}"
                    key = f"{key}~{k}"
                    report["renamed"].append({"from": "/".join(rel_parts + (name,)),
                                              "to": "/".join(rel_parts + (out_name,))})
                used.add(key)
                dest = dest_dir / out_name
                rel = rel_parts + (name,)

                if "files" in entry:
                    if depth + 1 > _ASAR_MAX_DEPTH:
                        skip("too_deep")
                        continue
                    if dest.is_symlink():
                        skip("dest_symlink")
                        continue
                    try:
                        dest.mkdir(exist_ok=True)
                    except OSError:
                        skip("write_failed")
                        continue
                    if not dest.is_dir():
                        skip("write_failed")
                        continue
                    report["dirs_created"] += 1
                    written_entries += 1
                    stack.append((entry, dest, rel, depth + 1))
                    continue
                if "link" in entry:
                    skip("symlink")
                    continue

                size = entry.get("size")
                if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                    skip("bad_size")
                    continue
                if total + size > max_total_bytes:
                    report["truncated"] = True
                    report["truncate_reason"] = (
                        f"toplam boyut bütçesi ({max_total_bytes} bayt)"
                    )
                    return report
                if dest.is_symlink():
                    skip("dest_symlink")
                    continue

                if entry.get("unpacked"):
                    if unpacked_real is None:
                        skip("unpacked_missing")
                        continue
                    src = unpacked_root.joinpath(*rel)
                    try:
                        st = os.lstat(src)
                    except OSError:
                        skip("unpacked_missing")
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        # simgesel bağ ya da özel dosya: izlenmez
                        skip("unpacked_not_regular")
                        continue
                    try:
                        src.resolve().relative_to(unpacked_real)
                    except ValueError:
                        skip("unpacked_outside")
                        continue
                    if st.st_size != size:
                        skip("unpacked_size_mismatch")
                        continue
                    try:
                        with open(src, "rb") as sfh:
                            _copy_exact(sfh, dest, size)
                    except OSError:
                        skip("write_failed")
                        continue
                    report["unpacked_files"] += 1
                else:
                    offset_raw = entry.get("offset")
                    try:
                        offset = int(offset_raw)
                    except (TypeError, ValueError):
                        skip("bad_offset")
                        continue
                    if offset < 0 or body_start + offset + size > file_size:
                        skip("out_of_bounds")
                        continue
                    fh.seek(body_start + offset)
                    try:
                        _copy_exact(fh, dest, size)
                    except OSError:
                        skip("write_failed")
                        continue
                total += size
                written_entries += 1
                report["files_written"] += 1
                report["bytes_written"] = total
    return report


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
        # Son ASAR acma raporu (extract_asar); analyze_static stats'a yazar.
        self.last_asar_report: dict[str, Any] | None = None

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
            self.last_asar_report = None
            extract_success = self._extract_asar(asar_path, extract_dir)
            if self.last_asar_report is not None:
                stats["asar_extract"] = self.last_asar_report

            if not extract_success:
                reason = (self.last_asar_report or {}).get("error")
                errors.append(
                    f"ASAR extract basarisiz: {asar_path}"
                    + (f" ({reason})" if reason else "")
                )
                return StageResult(
                    stage_name="static",
                    success=False,
                    duration_seconds=time.monotonic() - start,
                    stats=stats,
                    errors=errors,
                )

            if (self.last_asar_report or {}).get("truncated"):
                errors.append(
                    "ASAR kismen acildi: "
                    f"{self.last_asar_report['truncate_reason']} asildi; "
                    f"{self.last_asar_report['files_written']} dosya cikarildi"
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
        """ASAR arsivini extract et (Python'da; ag ve alt surec YOK).

        BICIM-06: Eskiden ``npx --yes @electron/asar extract`` cagriliyordu
        (surumu sabitlenmemis paketi agdan indirip calistirir). Artik
        :func:`extract_asar` kullanilir; rapor ``self.last_asar_report``'ta.

        Args:
            asar_path: ASAR dosya yolu.
            output_dir: Extract edilecek dizin.

        Returns:
            En az bir dosya cikarildiysa True.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(
            "ASAR extract baslatiliyor: %s -> %s",
            asar_path.name, output_dir,
        )
        try:
            report = extract_asar(
                asar_path, output_dir,
                max_total_bytes=int(self.config.security.max_archive_extract_size),
            )
        except (AsarFormatError, OSError) as exc:
            self.last_asar_report = {"format": "asar", "error": str(exc)}
            logger.error("ASAR extract basarisiz: %s", exc)
            return False
        self.last_asar_report = report

        if report["skipped"] or report["renamed"] or report["truncated"]:
            logger.warning(
                "ASAR extract: atlanan=%s, yeniden adlandirilan=%d, kesildi=%s",
                report["skipped"], len(report["renamed"]),
                report["truncate_reason"] or "hayir",
            )
        if report["files_written"] == 0:
            logger.error("ASAR extract sonrasi dosya yok: %s", output_dir)
            return False

        logger.info(
            "ASAR extract basarili: %d dosya cikarildi (%d bayt)",
            report["files_written"], report["bytes_written"],
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
                main_entry = pkg.get("main", "") if isinstance(pkg, dict) else ""
                if main_entry and isinstance(main_entry, str):
                    main_path = extract_dir / main_entry
                    # "/abs/x.js" ya da "../../x.js" analistin diskindeki başka
                    # bir dosyayı "ana JS" seçtirmesin: çıkarım kökünde kalmalı.
                    try:
                        main_path.resolve().relative_to(extract_dir.resolve())
                        inside = True
                    except (ValueError, OSError):
                        inside = False
                    if not inside:
                        logger.warning(
                            "package.json main cikarim dizini disini gosteriyor, "
                            "yok sayildi",
                        )
                    elif main_path.exists() and main_path.suffix in (".js", ".mjs", ".cjs"):
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
