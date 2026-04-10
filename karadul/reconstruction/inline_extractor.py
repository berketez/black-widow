"""Inline Anthropic kod bolgelerini ana bundle'dan cikar.

Claude Code CLI gibi buyuk JS bundle'larinda Anthropic'in kendi kodu
webpack modulu olarak degil, inline olarak gomulu. Bu class
scripts/extract-inline-regions.mjs'yi calistirir ve sonuclari
calistiriilabilir proje yapisina donusturur.
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import Config
from karadul.core.subprocess_runner import SubprocessRunner

logger = logging.getLogger(__name__)


@dataclass
class InlineExtractionResult:
    """Inline extraction sonucu.

    Attributes:
        success: Basarili tamamlanip tamamlanmadigi.
        regions_found: Bulunan bolge sayisi.
        total_lines_extracted: Cikarilan toplam satir sayisi.
        coverage_percent: Kaynak dosyanin ne kadari kapsanmis.
        regions: Her bolgenin detaylari.
        cross_references: Bolgeler arasi cross-reference sayisi.
        output_dir: Cikti dizini.
        errors: Hata mesajlari.
    """

    success: bool = False
    regions_found: int = 0
    total_lines_extracted: int = 0
    coverage_percent: float = 0.0
    regions: list[dict[str, Any]] = field(default_factory=list)
    cross_references: int = 0
    output_dir: Path | None = None
    errors: list[str] = field(default_factory=list)


# Inline bolgelerin proje yapisindaki hedef konumlari
_REGION_TO_PROJECT_PATH = {
    "tool-definitions": "src/tools",
    "mcp-server": "src/mcp",
    "permission-system": "src/permissions",
    "api-client": "src/api",
    "model-selection": "src/models",
    "system-prompt": "src/prompt",
    "config-reader": "src/config",
    "cli-commands": "src/cli",
    "hooks-system": "src/hooks",
    "streaming": "src/streaming",
    "oauth-auth": "src/auth",
    "telemetry": "src/telemetry",
}


class InlineExtractor:
    """Inline Anthropic kodunu ana bundle'dan cikar.

    scripts/extract-inline-regions.mjs'yi calistirarak beautified JS
    dosyasindan anchor pattern'ler ile anlamli kod bolgelerini bulur
    ve ayri dosyalara yazar.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.runner = SubprocessRunner(config)

    def extract(self, beautified_js: Path, output_dir: Path) -> InlineExtractionResult:
        """Inline bolgeleri cikar.

        Args:
            beautified_js: Beautified JS dosyasi.
            output_dir: Cikarilan bolgelerin yazilacagi dizin.

        Returns:
            InlineExtractionResult: Extraction sonucu.
        """
        result = InlineExtractionResult()

        script_path = self.config.scripts_dir / "extract-inline-regions.mjs"
        if not script_path.exists():
            result.errors.append(f"Script bulunamadi: {script_path}")
            return result

        if not beautified_js.exists():
            result.errors.append(f"Kaynak dosya bulunamadi: {beautified_js}")
            return result

        # Cikti dizinini olustur
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Node.js scripti calistir
            parsed = self.runner.run_node_script(
                script_path,
                args=[str(beautified_js), str(output_dir)],
                timeout=180,  # 3 dakika -- buyuk dosya
            )

            result.success = parsed.get("success", False)
            result.regions_found = parsed.get("regions_found", 0)
            result.total_lines_extracted = parsed.get("total_lines_extracted", 0)
            result.coverage_percent = parsed.get("coverage_percent", 0.0)
            result.regions = parsed.get("regions", [])
            result.cross_references = parsed.get("cross_references", 0)
            result.output_dir = output_dir

            logger.info(
                "Inline extraction: %d bolge, %d satir, %.1f%% kapsam",
                result.regions_found,
                result.total_lines_extracted,
                result.coverage_percent,
            )

        except RuntimeError as exc:
            result.errors.append(f"Script calismasi basarisiz: {exc}")
            logger.error("Inline extraction hatasi: %s", exc)

        except Exception as exc:
            result.errors.append(f"Beklenmeyen hata: {type(exc).__name__}: {exc}")
            logger.exception("Inline extraction exception")

        return result

    def create_project(self, regions_dir: Path, output_dir: Path) -> Path:
        """Cikarilan bolgelerden calistiriilabilir proje olustur.

        Her bolgeyi uygun src/ alt dizinine yerlestirir ve
        package.json, README ve index.js olusturur.

        Args:
            regions_dir: extract() ile olusturulan bolge dosyalarinin dizini.
            output_dir: Proje cikti dizini.

        Returns:
            Olusturulan proje dizininin yolu.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Manifest oku
        manifest_path = regions_dir / "manifest.json"
        manifest = {}
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Manifest okunamadi: %s", exc)

        regions = manifest.get("regions", [])

        # src/ alt dizinlerini olustur ve bolgeleri kopyala
        files_written = 0
        for region in regions:
            anchor = region.get("anchor", "unknown")
            src_file = region.get("file", "")

            # Hedef dizini belirle
            target_subdir = _REGION_TO_PROJECT_PATH.get(anchor, f"src/{anchor}")
            target_dir = output_dir / target_subdir
            target_dir.mkdir(parents=True, exist_ok=True)

            # Dosyayi kopyala
            src_path = regions_dir / src_file
            if src_path.exists():
                dest_path = target_dir / src_file
                shutil.copy2(str(src_path), str(dest_path))
                files_written += 1

        # package.json olustur
        pkg = {
            "name": "claude-code-extracted",
            "version": "0.0.1",
            "description": "Extracted inline regions from Claude Code CLI",
            "type": "module",
            "main": "src/cli/index.js",
            "scripts": {
                "start": "echo 'Extracted regions -- not directly runnable'",
                "lint": "echo 'No lint configured'",
            },
            "private": True,
            "dependencies": {},
            "devDependencies": {},
        }

        pkg_path = output_dir / "package.json"
        pkg_path.write_text(json.dumps(pkg, indent=2), encoding="utf-8")

        # index.js -- her bolgeyi listele
        index_lines = [
            "// Claude Code CLI -- Extracted Inline Regions",
            "// This file lists all extracted regions for reference.",
            "//",
            f"// Total regions: {len(regions)}",
            f"// Source: {manifest.get('source', 'unknown')}",
            "",
        ]

        for region in regions:
            anchor = region.get("anchor", "unknown")
            target_subdir = _REGION_TO_PROJECT_PATH.get(anchor, f"src/{anchor}")
            index_lines.append(
                f"// {anchor}: ./{target_subdir}/{region.get('file', '?')} "
                f"(L{region.get('start_line', '?')}-{region.get('end_line', '?')}, "
                f"{region.get('line_count', '?')} lines)"
            )

        (output_dir / "index.js").write_text("\n".join(index_lines), encoding="utf-8")

        # INDEX.md kopyala
        index_md = regions_dir / "INDEX.md"
        if index_md.exists():
            shutil.copy2(str(index_md), str(output_dir / "REGIONS.md"))

        logger.info(
            "Proje olusturuldu: %s (%d dosya)",
            output_dir, files_written,
        )

        return output_dir
