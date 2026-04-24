"""Calistiriilabilir proje uretici.

Deobfuscate edilmis kodu `npm install && npm start` ile calisabilecek
bir projeye donusturur. package.json, entry point, README, .env.example
ve opsiyonel Dockerfile olusturur.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from karadul.config import Config
from karadul.core.target import TargetInfo
from karadul.core.workspace import Workspace

if TYPE_CHECKING:
    from karadul.reconstruction.dependency_resolver import DependencyResolver

logger = logging.getLogger(__name__)

# Node.js built-in modulleri -- bunlar dependency olarak eklenmez
NODE_BUILTINS = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster",
    "console", "constants", "crypto", "dgram", "diagnostics_channel",
    "dns", "domain", "events", "fs", "http", "http2", "https",
    "inspector", "module", "net", "os", "path", "perf_hooks",
    "process", "punycode", "querystring", "readline", "repl",
    "stream", "string_decoder", "sys", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
    # node: prefix'li olanlar
    "node:assert", "node:buffer", "node:child_process", "node:cluster",
    "node:console", "node:constants", "node:crypto", "node:dgram",
    "node:diagnostics_channel", "node:dns", "node:domain", "node:events",
    "node:fs", "node:http", "node:http2", "node:https", "node:inspector",
    "node:module", "node:net", "node:os", "node:path", "node:perf_hooks",
    "node:process", "node:punycode", "node:querystring", "node:readline",
    "node:repl", "node:stream", "node:string_decoder", "node:sys",
    "node:timers", "node:tls", "node:trace_events", "node:tty",
    "node:url", "node:util", "node:v8", "node:vm", "node:wasi",
    "node:worker_threads", "node:zlib",
    # Diger yaygin built-in referanslari
    "fs/promises", "path/posix", "path/win32", "dns/promises",
    "readline/promises", "stream/promises", "stream/web",
    "timers/promises", "util/types",
    "node:fs/promises", "node:path/posix", "node:path/win32",
})

# require/import tespiti regex
_REQUIRE_PATTERN = re.compile(
    r'require\s*\(\s*["\']([^"\']+)["\']\s*\)',
)
_IMPORT_PATTERN = re.compile(
    r'(?:import|from)\s+["\']([^"\']+)["\']',
)
_DYNAMIC_IMPORT_PATTERN = re.compile(
    r'import\s*\(\s*["\']([^"\']+)["\']\s*\)',
)


@dataclass
class BuildResult:
    """Proje build sonucu.

    Attributes:
        success: Build basarili mi.
        project_dir: Olusturulan proje dizini.
        package_json: package.json dosyasi yolu.
        entry_point: Ana dosya yolu.
        dependencies: Tespit edilen bagimliliklar.
        files_created: Olusturulan dosya listesi.
        errors: Hatalar.
    """

    success: bool
    project_dir: Path | None
    package_json: Path | None
    entry_point: Path | None
    dependencies: dict[str, str] = field(default_factory=dict)
    files_created: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ProjectBuilder:
    """Deobfuscate edilmis kodu calistiriilabilir projeye donustur.

    Args:
        config: Merkezi konfigurasyon.
        dependency_resolver: Opsiyonel DependencyResolver instance'i.
            Verilirse _detect_dependencies yerine bu kullanilir.
    """

    def __init__(
        self,
        config: Config,
        dependency_resolver: "DependencyResolver | None" = None,
    ) -> None:
        self.config = config
        self._dep_resolver = dependency_resolver

    def build(
        self,
        workspace: Workspace,
        target: TargetInfo,
        split_result: Any | None = None,
        gap_result: Any | None = None,
    ) -> BuildResult:
        """Calistiriilabilir proje olustur.

        1. package.json olustur (isim, dependencies, scripts)
        2. Entry point belirle ve olustur
        3. .env.example olustur
        4. README.md olustur
        5. Dockerfile olustur (opsiyonel)

        Args:
            workspace: Calisma dizini.
            target: Hedef dosya bilgileri.
            split_result: ModuleSplitter sonucu (varsa).
            gap_result: GapFiller sonucu (varsa).

        Returns:
            BuildResult: Sonuc.
        """
        errors: list[str] = []
        files_created: list[str] = []

        # Proje dizini
        project_dir = workspace.get_stage_dir("reconstructed") / "project"
        project_dir.mkdir(parents=True, exist_ok=True)
        src_dir = project_dir / "src"
        src_dir.mkdir(exist_ok=True)

        # Dependency tespiti
        if self._dep_resolver:
            # Gelismis dependency resolver kullan
            try:
                deob_dir = workspace.get_stage_dir("deobfuscated")
                deps = self._dep_resolver.resolve(deob_dir)
                logger.info("DependencyResolver: %d paket tespit edildi", len(deps))
            except Exception as exc:
                logger.warning("DependencyResolver hatasi, fallback: %s", exc)
                deps = self._detect_dependencies(workspace)
        else:
            deps = self._detect_dependencies(workspace)

        # Entry point
        entry_path = self._create_entry_point(
            workspace, project_dir, split_result,
        )
        if entry_path:
            files_created.append(str(entry_path.relative_to(project_dir)))

        # Environment variable'lar
        env_vars: list[str] = []
        if gap_result and hasattr(gap_result, "env_variables"):
            env_vars = gap_result.env_variables
        else:
            env_vars = self._scan_env_variables(workspace)

        # package.json
        try:
            pkg_path = self._create_package_json(
                project_dir, target, deps, entry_path,
            )
            files_created.append("package.json")
        except OSError as exc:
            errors.append(f"package.json olusturulamadi: {exc}")
            pkg_path = None

        # .env.example
        try:
            if env_vars:
                env_path = self._generate_env_example(project_dir, env_vars)
                files_created.append(".env.example")
            else:
                env_path = None
        except OSError as exc:
            errors.append(f".env.example olusturulamadi: {exc}")

        # README.md
        try:
            readme_path = self._generate_readme(
                project_dir, target, deps, env_vars, entry_path,
            )
            files_created.append("README.md")
        except OSError as exc:
            errors.append(f"README.md olusturulamadi: {exc}")

        # Dockerfile
        try:
            docker_path = self._generate_dockerfile(
                project_dir, entry_path,
            )
            files_created.append("Dockerfile")
        except OSError as exc:
            errors.append(f"Dockerfile olusturulamadi: {exc}")

        # .gitignore
        try:
            self._generate_gitignore(project_dir)
            files_created.append(".gitignore")
        except OSError as exc:
            errors.append(f".gitignore olusturulamadi: {exc}")

        success = pkg_path is not None
        logger.info(
            "Project build: %d dosya olusturuldu, %d dependency",
            len(files_created),
            len(deps),
        )

        return BuildResult(
            success=success,
            project_dir=project_dir,
            package_json=pkg_path,
            entry_point=entry_path,
            dependencies=deps,
            files_created=files_created,
            errors=errors,
        )

    def _detect_dependencies(self, workspace: Workspace) -> dict[str, str]:
        """Tum workspace JS dosyalarindan npm bagimlilikdarini tespit et.

        Node.js built-in modulleri ve relative import'lar haric tutulur.

        Returns:
            Paket adi -> versiyon eslesmesi (versiyon bilinmiyorsa "latest").
        """
        deps: dict[str, str] = {}

        # Tum JS dosyalarini tara
        for stage in ("deobfuscated", "reconstructed", "raw"):
            stage_dir = workspace.get_stage_dir(stage)
            if not stage_dir.exists():
                continue
            for js_file in stage_dir.rglob("*.js"):
                try:
                    content = js_file.read_text(
                        encoding="utf-8", errors="replace",
                    )
                    self._scan_dependencies(content, deps)
                except OSError:
                    pass

        return deps

    @staticmethod
    def _scan_dependencies(content: str, deps: dict[str, str]) -> None:
        """JS icerigindeki require/import statement'lardan paket isimlerini cikar."""
        for pattern in (_REQUIRE_PATTERN, _IMPORT_PATTERN, _DYNAMIC_IMPORT_PATTERN):
            for match in pattern.finditer(content):
                module_name = match.group(1)

                # Relative import'lari atla
                if module_name.startswith(".") or module_name.startswith("/"):
                    continue

                # Node built-in'leri atla
                if module_name in NODE_BUILTINS:
                    continue
                # node: prefix'li built-in'ler
                if module_name.startswith("node:"):
                    continue

                # Scoped package: @scope/package
                if module_name.startswith("@"):
                    parts = module_name.split("/")
                    if len(parts) >= 2:
                        pkg = f"{parts[0]}/{parts[1]}"
                    else:
                        continue
                else:
                    # Normal package: ilk / oncesini al
                    pkg = module_name.split("/")[0]

                if pkg and pkg not in deps:
                    deps[pkg] = "latest"

    def _create_entry_point(
        self,
        workspace: Workspace,
        project_dir: Path,
        split_result: Any | None = None,
    ) -> Path | None:
        """Ana giris noktasi dosyasi olustur.

        Args:
            workspace: Calisma dizini.
            project_dir: Proje dizini.
            split_result: ModuleSplitter sonucu (varsa).

        Returns:
            Entry point dosya yolu veya None.
        """
        src_dir = project_dir / "src"
        entry_file = src_dir / "index.js"

        # split_result'tan entry point varsa kopyala
        if split_result and hasattr(split_result, "entry_point") and split_result.entry_point:
            ep = split_result.entry_point
            if ep.exists():
                try:
                    content = ep.read_text(encoding="utf-8", errors="replace")
                    header = (
                        "/**\n"
                        " * Entry Point - Reconstructed by Karadul v1.0\n"
                        " * This is the main entry point of the reconstructed application.\n"
                        " */\n\n"
                    )
                    entry_file.write_text(header + content, encoding="utf-8")
                    return entry_file
                except OSError:
                    pass

        # Deobfuscated dosyalardan entry point ara
        deob_dir = workspace.get_stage_dir("deobfuscated")
        if deob_dir.exists():
            # module_0.js veya en buyuk beautified dosya
            candidates = list(deob_dir.glob("**/module_0*.js"))
            if not candidates:
                candidates = list(deob_dir.glob("**/*.beautified.js"))
            if not candidates:
                candidates = list(deob_dir.glob("**/*.js"))

            if candidates:
                # En buyuk dosyayi entry point olarak sec
                best = max(candidates, key=lambda f: f.stat().st_size)
                try:
                    content = best.read_text(encoding="utf-8", errors="replace")
                    header = (
                        "/**\n"
                        f" * Entry Point - Reconstructed from {best.name}\n"
                        " * Reconstructed by Karadul v1.0\n"
                        " */\n\n"
                    )
                    entry_file.write_text(header + content, encoding="utf-8")
                    return entry_file
                except OSError:
                    pass

        # Fallback: bos entry point
        entry_file.write_text(
            '/**\n'
            ' * Entry Point - Karadul v1.0 Reconstruction\n'
            ' * No entry point could be auto-detected.\n'
            ' * Add your main code here.\n'
            ' */\n\n'
            'console.log("Reconstructed project - ready for development");\n',
            encoding="utf-8",
        )
        return entry_file

    @staticmethod
    def _create_package_json(
        project_dir: Path,
        target: TargetInfo,
        deps: dict[str, str],
        entry_point: Path | None,
    ) -> Path:
        """package.json olustur.

        Args:
            project_dir: Proje dizini.
            target: Hedef bilgileri.
            deps: Bagimliliklar.
            entry_point: Entry point dosyasi.

        Returns:
            package.json dosya yolu.
        """
        # Entry point relative path
        if entry_point:
            try:
                main = str(entry_point.relative_to(project_dir))
            except ValueError:
                main = "src/index.js"
        else:
            main = "src/index.js"

        pkg = {
            "name": f"reconstructed-{target.name.lower().replace(' ', '-')}",
            "version": "1.0.0",
            "description": f"Reconstructed from {target.name} by Karadul v1.0",
            "main": main,
            "scripts": {
                "start": f"node {main}",
                "dev": f"node --watch {main}",
            },
            "keywords": ["reconstructed", "karadul"],
            "license": "UNLICENSED",
            "private": True,
            "dependencies": deps,
        }

        pkg_path = project_dir / "package.json"
        pkg_path.write_text(
            json.dumps(pkg, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return pkg_path

    @staticmethod
    def _generate_env_example(
        project_dir: Path,
        env_vars: list[str],
    ) -> Path:
        """Environment variable'lar icin .env.example olustur.

        Args:
            project_dir: Proje dizini.
            env_vars: Tespit edilen env variable listesi.

        Returns:
            .env.example dosya yolu.
        """
        lines = [
            "# Environment Variables",
            f"# Auto-detected by Karadul v1.0 ({len(env_vars)} variables found)",
            "",
        ]

        for var in sorted(env_vars):
            # Yaygin degiskenler icin aciklama ekle
            comment = ""
            var_lower = var.lower()
            if "port" in var_lower:
                comment = "  # Server port"
                lines.append(f"{var}=3000{comment}")
            elif "host" in var_lower:
                comment = "  # Server host"
                lines.append(f"{var}=localhost{comment}")
            elif "secret" in var_lower or "key" in var_lower:
                comment = "  # Secret key - change in production!"
                lines.append(f"{var}=change-me{comment}")
            elif "url" in var_lower or "uri" in var_lower:
                comment = "  # Service URL"
                lines.append(f"{var}=http://localhost:3000{comment}")
            elif "db" in var_lower or "database" in var_lower:
                comment = "  # Database connection"
                lines.append(f"{var}={comment}")
            elif "node_env" == var_lower:
                lines.append(f"{var}=development  # development | production | test")
            elif "debug" in var_lower:
                lines.append(f"{var}=true  # Enable debug mode")
            else:
                lines.append(f"{var}=")

        lines.append("")

        env_path = project_dir / ".env.example"
        env_path.write_text("\n".join(lines), encoding="utf-8")
        return env_path

    @staticmethod
    def _generate_readme(
        project_dir: Path,
        target: TargetInfo,
        deps: dict[str, str],
        env_vars: list[str],
        entry_point: Path | None,
    ) -> Path:
        """README.md olustur.

        Args:
            project_dir: Proje dizini.
            target: Hedef bilgileri.
            deps: Bagimliliklar.
            env_vars: Environment variable listesi.
            entry_point: Entry point dosyasi.

        Returns:
            README.md dosya yolu.
        """
        entry_rel = "src/index.js"
        if entry_point:
            try:
                entry_rel = str(entry_point.relative_to(project_dir))
            except ValueError:
                pass

        lines = [
            f"# reconstructed-{target.name}",
            "",
            f"Reconstructed from `{target.name}` using [Karadul v1.0](https://github.com/karadul) reverse engineering suite.",
            "",
            "## Quick Start",
            "",
            "```bash",
            "npm install",
            "npm start",
            "```",
            "",
            "## Project Structure",
            "",
            "```",
            f"  {entry_rel}   -- Main entry point",
            "  src/              -- Source files",
            "  package.json      -- Dependencies & scripts",
            "```",
            "",
        ]

        if deps:
            lines.extend([
                "## Dependencies",
                "",
                "| Package | Version |",
                "|---------|---------|",
            ])
            for pkg, ver in sorted(deps.items()):
                lines.append(f"| {pkg} | {ver} |")
            lines.append("")

        if env_vars:
            lines.extend([
                "## Environment Variables",
                "",
                "Copy `.env.example` to `.env` and fill in the values:",
                "",
                "```bash",
                "cp .env.example .env",
                "```",
                "",
                "| Variable | Description |",
                "|----------|-------------|",
            ])
            for var in sorted(env_vars):
                lines.append(f"| `{var}` | |")
            lines.append("")

        lines.extend([
            "## Notes",
            "",
            "- This project was automatically reconstructed from an obfuscated/minified source.",
            "- Variable names have been inferred from context and may not match the original.",
            "- Some functionality may require additional configuration or external services.",
            f"- Original file: `{target.path.name}` ({target.file_size:,} bytes)",
            "",
            "---",
            "*Generated by Karadul v1.0*",
            "",
        ])

        readme_path = project_dir / "README.md"
        readme_path.write_text("\n".join(lines), encoding="utf-8")
        return readme_path

    @staticmethod
    def _generate_dockerfile(
        project_dir: Path,
        entry_point: Path | None,
    ) -> Path:
        """Dockerfile olustur.

        Args:
            project_dir: Proje dizini.
            entry_point: Entry point dosyasi.

        Returns:
            Dockerfile dosya yolu.
        """
        entry_rel = "src/index.js"
        if entry_point:
            try:
                entry_rel = str(entry_point.relative_to(project_dir))
            except ValueError:
                pass

        content = f"""\
# Reconstructed by Karadul v1.0
FROM node:20-alpine

WORKDIR /app

# Dependencies
COPY package*.json ./
RUN npm ci --only=production

# Source
COPY . .

# Expose port (adjust as needed)
EXPOSE 3000

CMD ["node", "{entry_rel}"]
"""

        docker_path = project_dir / "Dockerfile"
        docker_path.write_text(content, encoding="utf-8")
        return docker_path

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

    def _scan_env_variables(self, workspace: Workspace) -> list[str]:
        """Workspace dosyalarindan process.env referanslarini tara.

        GapFiller'in env_variables listesi yoksa fallback olarak kullanilir.
        """
        env_vars: set[str] = set()
        env_pattern = re.compile(
            r"process\.env\.(\w+)|process\.env\[[\"'](\w+)[\"']\]",
        )

        for stage in ("deobfuscated", "raw", "reconstructed"):
            stage_dir = workspace.get_stage_dir(stage)
            if not stage_dir.exists():
                continue
            for js_file in stage_dir.rglob("*.js"):
                try:
                    content = js_file.read_text(
                        encoding="utf-8", errors="replace",
                    )
                    for match in env_pattern.finditer(content):
                        var = match.group(1) or match.group(2)
                        if var:
                            env_vars.add(var)
                except OSError:
                    pass

        return sorted(env_vars)
