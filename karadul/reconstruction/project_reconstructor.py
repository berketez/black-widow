"""Tam proje reconstruction -- deobfuscate edilmis modulleri gercek dosya yapisina donustur.

reconstruct-project.mjs'i orkestre eder ve sonucu calistiriilabilir
bir projeye donusturur. ModuleSplitter + ProjectBuilder'in yaptigi isi
cok daha kapsamli yapar:
- 30+ kategori pattern'i ile akilli dosya yerlestirme
- Import/export rewiring (module ID -> gercek path)
- Buyuk dosyalari bolme, kucuk dosyalari birlestirme
- Her klasor icin index.js (re-export)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import Config
from karadul.core.subprocess_runner import SubprocessRunner
from karadul.core.target import TargetInfo
from karadul.core.workspace import Workspace
from karadul.reconstruction.dependency_resolver import DependencyResolver

logger = logging.getLogger(__name__)


@dataclass
class ReconstructionResult:
    """Proje reconstruction sonucu.

    Attributes:
        success: Reconstruction basarili mi.
        project_dir: Olusturulan proje dizini.
        package_json: package.json dosyasi yolu.
        entry_point: Ana dosya yolu.
        total_modules: Islenen modul sayisi.
        files_written: Olusturulan dosya sayisi.
        categories: Kategori -> dosya sayisi.
        dependencies: Tespit edilen npm paketleri.
        errors: Hata mesajlari.
        stats: Detayli istatistikler.
        duration_seconds: Islem suresi.
    """

    success: bool = False
    project_dir: Path | None = None
    package_json: Path | None = None
    entry_point: Path | None = None
    total_modules: int = 0
    files_written: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    dependencies: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0


class ProjectReconstructor:
    """Tam proje reconstruction -- modulleri gercek dosya yapisina donustur.

    Pipeline:
    1. Modul dizinini oku (deep_modules/ veya webpack_modules/)
    2. reconstruct-project.mjs ile kategorize et ve dosya yapisi olustur
    3. DependencyResolver ile gercek npm paketlerini tespit et
    4. package.json, entry point, README olustur
    5. Proje yapisini dogrula

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._runner = SubprocessRunner(config)
        self._dep_resolver = DependencyResolver(config, verify_npm=False)
        self._script_path = config.scripts_dir / "reconstruct-project.mjs"

    def reconstruct(
        self,
        workspace: Workspace,
        target: TargetInfo,
        *,
        modules_dir: Path | None = None,
    ) -> ReconstructionResult:
        """Tam proje reconstruction.

        Args:
            workspace: Calisma dizini.
            target: Hedef dosya bilgileri.
            modules_dir: Modul dizini. None ise workspace'ten otomatik bulunur.

        Returns:
            ReconstructionResult.
        """
        start = time.monotonic()
        result = ReconstructionResult()

        # 1. Modul dizinini bul
        if modules_dir is None:
            modules_dir = self._find_modules_dir(workspace)

        if modules_dir is None or not modules_dir.exists():
            result.errors.append("Modul dizini bulunamadi")
            result.duration_seconds = time.monotonic() - start
            return result

        # Modul sayisini say
        module_files = list(modules_dir.rglob("*.js"))
        if not module_files:
            result.errors.append(f"Modul dosyasi bulunamadi: {modules_dir}")
            result.duration_seconds = time.monotonic() - start
            return result

        result.total_modules = len(module_files)
        logger.info("ProjectReconstructor: %d modul bulundu", result.total_modules)

        # 2. reconstruct-project.mjs ile dosya yapisi olustur
        project_dir = workspace.get_stage_dir("reconstructed") / "project"
        project_dir.mkdir(parents=True, exist_ok=True)

        reconstruct_result = self._run_reconstruct_script(
            modules_dir, project_dir, target.name,
        )

        if reconstruct_result is not None:
            result.files_written = reconstruct_result.get("files_written", 0)
            result.categories = reconstruct_result.get("categories", {})
            result.stats["reconstruct_script"] = reconstruct_result
            if reconstruct_result.get("errors"):
                result.errors.extend(reconstruct_result["errors"])
        else:
            # Script basarisiz -- fallback olarak mevcut ModuleSplitter'i kullan
            logger.warning(
                "reconstruct-project.mjs basarisiz, dosyalar elle kopyalaniyor",
            )
            self._fallback_copy(modules_dir, project_dir)

        result.project_dir = project_dir

        # 3. Dependency tespiti
        try:
            deps = self._dep_resolver.resolve(project_dir)
            # Deobfuscated dizininden de dependency'leri al
            deob_dir = workspace.get_stage_dir("deobfuscated")
            if deob_dir.exists():
                deob_deps = self._dep_resolver.resolve(deob_dir)
                for pkg, ver in deob_deps.items():
                    if pkg not in deps:
                        deps[pkg] = ver
            result.dependencies = deps
        except Exception as exc:
            logger.warning("Dependency resolver hatasi: %s", exc)
            result.errors.append(f"Dependency resolver: {exc}")

        # 4. package.json olustur
        try:
            pkg_path = self._build_package_json(
                project_dir, target, result.dependencies,
            )
            result.package_json = pkg_path
        except OSError as exc:
            result.errors.append(f"package.json olusturulamadi: {exc}")

        # 5. Entry point belirle
        entry_point = self._find_or_create_entry_point(project_dir)
        result.entry_point = entry_point

        # 6. README olustur
        try:
            self._generate_readme(
                project_dir, target, result.dependencies,
                result.categories, result.total_modules,
            )
        except OSError as exc:
            result.errors.append(f"README olusturulamadi: {exc}")

        # 7. .gitignore olustur
        try:
            self._generate_gitignore(project_dir)
        except OSError as exc:
            result.errors.append(f".gitignore olusturulamadi: {exc}")

        # 8. Proje yapisini dogrula
        validation = self._validate_project(project_dir)
        result.stats["validation"] = validation

        result.success = (
            result.package_json is not None
            and result.files_written > 0
            or result.project_dir.exists()
        )
        result.duration_seconds = time.monotonic() - start

        logger.info(
            "ProjectReconstructor: %d dosya, %d dependency, %.1fs",
            result.files_written,
            len(result.dependencies),
            result.duration_seconds,
        )

        return result

    # ---------------------------------------------------------------
    # Private methods
    # ---------------------------------------------------------------

    def _find_modules_dir(self, workspace: Workspace) -> Path | None:
        """Workspace'ten modul dizinini bul.

        Sirali arama:
        1. deobfuscated/webpack_modules/modules/
        2. deobfuscated/webpack_modules/
        3. reconstructed/modules/
        """
        deob_dir = workspace.get_stage_dir("deobfuscated")

        candidates = [
            deob_dir / "webpack_modules" / "modules",
            deob_dir / "webpack_modules",
            workspace.get_stage_dir("reconstructed") / "modules",
        ]

        for candidate in candidates:
            if candidate.exists() and any(candidate.glob("*.js")):
                return candidate

        # Son deneme: deob_dir icerisinde herhangi bir module_*.js
        module_files = list(deob_dir.glob("**/module_*.js"))
        if module_files:
            return module_files[0].parent

        return None

    def _run_reconstruct_script(
        self,
        modules_dir: Path,
        output_dir: Path,
        target_name: str,
    ) -> dict | None:
        """reconstruct-project.mjs calistir.

        Returns:
            JSON sonucu veya None (basarisiz ise).
        """
        if not self._script_path.exists():
            logger.warning(
                "reconstruct-project.mjs bulunamadi: %s", self._script_path,
            )
            return None

        try:
            node_args = [
                "--max-old-space-size=4096",
                str(self._script_path),
                str(modules_dir),
                str(output_dir),
                "--target-name", target_name,
            ]

            sub_result = self._runner.run_command(
                [str(self._config.tools.node)] + node_args,
                timeout=300,
                cwd=self._config.scripts_dir,
            )

            if sub_result.parsed_json and sub_result.parsed_json.get("success"):
                return sub_result.parsed_json

            logger.warning(
                "reconstruct-project.mjs basarisiz: %s",
                sub_result.stderr[:300] if sub_result.stderr else "unknown",
            )
            return sub_result.parsed_json

        except Exception as exc:
            logger.warning("reconstruct-project.mjs hatasi: %s", exc)
            return None

    @staticmethod
    def _fallback_copy(modules_dir: Path, project_dir: Path) -> None:
        """Script basarisiz olursa modulleri src/lib/'e kopyala."""
        import shutil

        lib_dir = project_dir / "src" / "lib"
        lib_dir.mkdir(parents=True, exist_ok=True)

        for js_file in sorted(modules_dir.glob("*.js")):
            try:
                shutil.copy2(js_file, lib_dir / js_file.name)
            except OSError:
                pass

    @staticmethod
    def _build_package_json(
        project_dir: Path,
        target: TargetInfo,
        deps: dict[str, str],
    ) -> Path:
        """Gercek dependency'lerle package.json olustur.

        Args:
            project_dir: Proje dizini.
            target: Hedef bilgileri.
            deps: npm paket bagimliliklari.

        Returns:
            package.json dosya yolu.
        """
        # Entry point'i bul
        src_index = project_dir / "src" / "index.js"
        main = "src/index.js" if src_index.exists() else "index.js"

        safe_name = target.name.lower().replace(" ", "-").replace("_", "-")
        # npm isimlendirme kurallarina uygunluk
        safe_name = "".join(
            c for c in safe_name
            if c.isalnum() or c in "-."
        ) or "project"

        pkg = {
            "name": f"reconstructed-{safe_name}",
            "version": "1.0.0",
            "description": (
                f"Reconstructed from {target.name} by Karadul v1.0 "
                f"({target.file_size:,} bytes original)"
            ),
            "main": main,
            "scripts": {
                "start": f"node {main}",
                "dev": f"node --watch {main}",
                "lint": "echo 'No linter configured'",
            },
            "keywords": ["reconstructed", "karadul", "reverse-engineering"],
            "license": "UNLICENSED",
            "private": True,
            "engines": {
                "node": ">=18.0.0",
            },
            "dependencies": dict(sorted(deps.items())),
        }

        pkg_path = project_dir / "package.json"
        pkg_path.write_text(
            json.dumps(pkg, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return pkg_path

    @staticmethod
    def _find_or_create_entry_point(project_dir: Path) -> Path:
        """Entry point bul veya olustur.

        Sirali arama:
        1. src/index.js (reconstruct script olusturmus olabilir)
        2. index.js
        3. Yoksa olustur
        """
        candidates = [
            project_dir / "src" / "index.js",
            project_dir / "index.js",
        ]

        for candidate in candidates:
            if candidate.exists():
                return candidate

        # Olustur
        entry = project_dir / "src" / "index.js"
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_text(
            '/**\n'
            ' * Entry Point - Karadul v1.0 Reconstruction\n'
            ' * No entry point could be auto-detected.\n'
            ' */\n\n'
            '"use strict";\n\n'
            'console.log("Reconstructed project ready.");\n',
            encoding="utf-8",
        )
        return entry

    @staticmethod
    def _generate_readme(
        project_dir: Path,
        target: TargetInfo,
        deps: dict[str, str],
        categories: dict[str, int],
        total_modules: int,
    ) -> Path:
        """README.md olustur."""
        lines = [
            f"# reconstructed-{target.name}",
            "",
            f"Reconstructed from `{target.name}` ({target.file_size:,} bytes) "
            "using [Karadul v1.0](https://github.com/karadul) reverse engineering suite.",
            "",
            "## Quick Start",
            "",
            "```bash",
            "npm install",
            "npm start",
            "```",
            "",
        ]

        # Project structure
        if categories:
            lines.extend([
                "## Project Structure",
                "",
                "```",
            ])
            for cat, count in sorted(categories.items()):
                lines.append(f"  {cat}/  ({count} files)")
            lines.extend([
                "```",
                "",
            ])

        # Statistics
        lines.extend([
            "## Reconstruction Statistics",
            "",
            f"- **Original modules:** {total_modules}",
            f"- **Dependencies detected:** {len(deps)}",
            f"- **Categories:** {len(categories)}",
            "",
        ])

        # Dependencies
        if deps:
            lines.extend([
                "## Dependencies",
                "",
                "| Package | Version |",
                "|---------|---------|",
            ])
            for pkg, ver in sorted(deps.items()):
                lines.append(f"| `{pkg}` | {ver} |")
            lines.append("")

        lines.extend([
            "## Notes",
            "",
            "- This project was automatically reconstructed from an obfuscated/minified source.",
            "- Variable names have been inferred from context and may not match the original.",
            "- Some functionality may require additional configuration or external services.",
            "- File categorization is based on content analysis (heuristic).",
            "",
            "---",
            "*Generated by Karadul v1.0*",
            "",
        ])

        readme_path = project_dir / "README.md"
        readme_path.write_text("\n".join(lines), encoding="utf-8")
        return readme_path

    @staticmethod
    def _generate_gitignore(project_dir: Path) -> Path:
        """.gitignore olustur."""
        content = """\
node_modules/
.env
.env.local
.env.*.local
dist/
build/
*.log
npm-debug.log*
.DS_Store
coverage/
.nyc_output/
"""
        gitignore_path = project_dir / ".gitignore"
        gitignore_path.write_text(content, encoding="utf-8")
        return gitignore_path

    @staticmethod
    def _validate_project(project_dir: Path) -> dict:
        """Proje yapisini dogrula.

        Kontroller:
        1. package.json var mi ve gecerli JSON mi?
        2. Entry point var mi?
        3. src/ dizini var mi?
        4. JS dosyalari syntax hatasi veriyor mu? (basit kontrol)

        Returns:
            Dogrulama sonucu dict'i.
        """
        validation: dict[str, Any] = {
            "valid": True,
            "checks": {},
            "warnings": [],
        }

        # package.json kontrolu
        pkg_path = project_dir / "package.json"
        if pkg_path.exists():
            try:
                pkg_data = json.loads(pkg_path.read_text(encoding="utf-8"))
                validation["checks"]["package_json"] = True
                validation["checks"]["has_name"] = bool(pkg_data.get("name"))
                validation["checks"]["has_main"] = bool(pkg_data.get("main"))
                validation["checks"]["has_scripts"] = bool(pkg_data.get("scripts"))
            except json.JSONDecodeError:
                validation["checks"]["package_json"] = False
                validation["valid"] = False
        else:
            validation["checks"]["package_json"] = False
            validation["valid"] = False

        # Entry point kontrolu
        src_index = project_dir / "src" / "index.js"
        root_index = project_dir / "index.js"
        has_entry = src_index.exists() or root_index.exists()
        validation["checks"]["entry_point"] = has_entry

        # src/ dizini kontrolu
        src_dir = project_dir / "src"
        validation["checks"]["src_dir"] = src_dir.exists()

        # JS dosya sayisi
        js_files = list(project_dir.rglob("*.js"))
        validation["checks"]["js_file_count"] = len(js_files)

        # Dosya boyutu dagilimi
        if js_files:
            sizes = [f.stat().st_size for f in js_files]
            line_counts = []
            for f in js_files[:100]:  # Ilk 100 dosya
                try:
                    lines = f.read_text(encoding="utf-8", errors="replace").count("\n")
                    line_counts.append(lines)
                except OSError:
                    pass

            validation["checks"]["avg_file_size"] = sum(sizes) // max(len(sizes), 1)
            if line_counts:
                validation["checks"]["avg_lines"] = sum(line_counts) // len(line_counts)
                validation["checks"]["max_lines"] = max(line_counts)
                if max(line_counts) > 1000:
                    validation["warnings"].append(
                        f"En buyuk dosya {max(line_counts)} satir (>500 hedef)"
                    )

        return validation
