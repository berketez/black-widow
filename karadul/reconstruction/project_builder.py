"""Analiz için proje iskeleti üretici.

Deobfuscate edilmiş kodu bir proje düzenine (package.json, giriş dosyası,
README, .env.example, Dockerfile) yerleştirir. Bu kod ANALİZ EDİLEN
(güvenilmeyen, zararlı olabilecek) yazılımdır: README çalıştırmayı önermez,
çalıştırmamayı söyler (BICIM-12). Giriş dosyası bulunamazsa uydurma kod
yazılmaz.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from karadul import __version__ as KARADUL_VERSION
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


# BICIM-12: üretilen README'lerin başındaki uyarı (ProjectReconstructor da
# kullanır). Eskiden README "Quick Start: npm install / npm start" ile analiz
# edilen kodu çalıştırmayı öneriyordu; `npm install` paket betiklerini
# (postinstall) de çalıştırır.
UNTRUSTED_CODE_WARNING: tuple[str, ...] = (
    "## ⚠ Do not run this code / Bu kodu çalıştırmayın",
    "",
    "This directory was generated from the **analyzed (untrusted, possibly "
    "malicious) software**. It is for reading and static analysis only.",
    "Do **not** run `npm install`, `npm start`, `node` or `docker run` on it on "
    "your machine: `npm install` also executes package scripts (postinstall) "
    "and the dependency names are the ones the analyzed code requires.",
    "If dynamic analysis is needed, use an isolated, disposable environment "
    "without network access.",
    "",
    "Bu dizin **analiz edilen (güvenilmeyen, zararlı olabilecek) yazılımdan** "
    "üretildi; yalnız okuma ve statik inceleme içindir. Kendi makinenizde "
    "`npm install`, `npm start`, `node` ya da `docker run` ile çalıştırmayın. "
    "Dinamik inceleme gerekiyorsa ağsız, yalıtılmış ve atılabilir bir ortam kullanın.",
    "",
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
        named_source: Path | None = None,
    ) -> BuildResult:
        """Analiz için proje iskeleti oluştur.

        ``named_source`` (BICIM-12): JS hattının son çıktısı (adlandırılmış /
        tiplenmiş / yorumlanmış dosya). Verilirse giriş dosyası odur; eskiden
        giriş tek bir webpack modülünden (``module_0``) kuruluyor, ad adımlarının
        sonucu projeye hiç girmiyordu. Çağıran (``stages.py`` ``_execute_js``)
        bunu P-S4'te geçirecek.

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
            workspace, project_dir, split_result, named_source=named_source,
        )
        if entry_path:
            files_created.append(str(entry_path.relative_to(project_dir)))
        else:
            # Uydurma giriş yazılmaz (eskiden "ready for development" diyen,
            # hedefle ilgisiz bir console.log yazılıyordu).
            errors.append("Giriş dosyası bulunamadı; proje giriş dosyasız kuruldu")

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

        # Dockerfile (yalnız giriş varsa; yalıtılmış dinamik inceleme içindir)
        if entry_path is not None:
            try:
                self._generate_dockerfile(project_dir, entry_path)
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
        *,
        named_source: Path | None = None,
    ) -> Path | None:
        """Ana giris noktasi dosyasi olustur.

        Args:
            workspace: Calisma dizini.
            project_dir: Proje dizini.
            split_result: ModuleSplitter sonucu (varsa).
            named_source: JS hattının son (adlandırılmış) çıktısı; önceliklidir.

        Returns:
            Entry point dosya yolu veya None (aday yoksa; uydurma dosya yazılmaz).
        """
        src_dir = project_dir / "src"
        entry_file = src_dir / "index.js"

        # BICIM-12: ad / tip / yorum adımlarının son çıktısı önce gelir.
        if named_source is not None and named_source.is_file():
            try:
                content = named_source.read_text(encoding="utf-8", errors="replace")
                header = (
                    "/**\n"
                    f" * Entry Point - named output {named_source.name}\n"
                    f" * Reconstructed by Karadul {KARADUL_VERSION} from the analyzed "
                    "(untrusted) software. Do not run.\n"
                    " */\n\n"
                )
                entry_file.write_text(header + content, encoding="utf-8")
                return entry_file
            except OSError:
                pass

        # split_result'tan entry point varsa kopyala
        if split_result and hasattr(split_result, "entry_point") and split_result.entry_point:
            ep = split_result.entry_point
            if ep.exists():
                try:
                    content = ep.read_text(encoding="utf-8", errors="replace")
                    header = (
                        "/**\n"
                        f" * Entry Point - Reconstructed by Karadul {KARADUL_VERSION}\n"
                        " * From the analyzed (untrusted) software. Do not run.\n"
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
                        f" * Reconstructed by Karadul {KARADUL_VERSION} from the analyzed "
                        "(untrusted) software. Do not run.\n"
                        " */\n\n"
                    )
                    entry_file.write_text(header + content, encoding="utf-8")
                    return entry_file
                except OSError:
                    pass

        # Aday yok: uydurma giriş YAZILMAZ (BICIM-12). Eskiden hedefle ilgisiz
        # 'console.log("Reconstructed project - ready for development")' yazılıyordu.
        return None

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
        # Entry point relative path (giriş yoksa main / scripts yazılmaz:
        # var olmayan bir dosyayı gösteren "start" betiği uydurma olurdu)
        main: str | None = None
        if entry_point:
            try:
                main = str(entry_point.relative_to(project_dir))
            except ValueError:
                main = "src/index.js"

        pkg: dict[str, Any] = {
            "name": f"reconstructed-{target.name.lower().replace(' ', '-')}",
            "version": "1.0.0",
            "description": (
                f"Reconstructed from {target.name} by Karadul {KARADUL_VERSION}. "
                "Analyzed (untrusted) software - do not run outside an isolated environment."
            ),
            "keywords": ["reconstructed", "karadul"],
            "license": "UNLICENSED",
            "private": True,
            "dependencies": deps,
        }
        if main is not None:
            # `karadul run` (kapılı, P-GÜV) bu betiği kullanır; README önermez.
            pkg["main"] = main
            pkg["scripts"] = {
                "start": f"node {main}",
                "dev": f"node --watch {main}",
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
            f"# Auto-detected by Karadul {KARADUL_VERSION} ({len(env_vars)} variables found)",
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
        entry_rel: str | None = None
        if entry_point:
            try:
                entry_rel = str(entry_point.relative_to(project_dir))
            except ValueError:
                entry_rel = "src/index.js"

        lines = [
            f"# reconstructed-{target.name}",
            "",
            f"Reconstructed from `{target.name}` by Karadul {KARADUL_VERSION} "
            "(reverse engineering suite).",
            "",
            *UNTRUSTED_CODE_WARNING,
            "## Project Structure",
            "",
            "```",
            (
                f"  {entry_rel}   -- Entry point (reconstructed)"
                if entry_rel else
                "  (no entry point could be identified)"
            ),
            "  src/              -- Source files",
            "  package.json      -- Dependencies as required by the analyzed code",
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
                "Environment variables read by the analyzed code (see `.env.example`):",
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
            f"- Original file: `{target.path.name}` ({target.file_size:,} bytes)",
            "",
            "---",
            f"*Generated by Karadul {KARADUL_VERSION}*",
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

        # BICIM-12: eskiden `npm ci --only=production` (kilit dosyası yok, zaten
        # derlenmiyordu) ve uyarısızdı. Bu dosya yalnız yalıtılmış dinamik
        # inceleme içindir; paket betikleri kapalı kurulur.
        content = f"""\
# Reconstructed by Karadul {KARADUL_VERSION} from the ANALYZED (untrusted,
# possibly malicious) software. For isolated dynamic analysis ONLY.
# Bu kod analiz edilen yazılımdır; yalnız yalıtılmış ortamda çalıştırın.
# Run without network access, e.g.: docker run --rm --network none <image>
FROM node:20-alpine

WORKDIR /app

# Dependencies (package scripts disabled)
COPY package*.json ./
RUN npm install --ignore-scripts --no-audit --no-fund

# Source
COPY . .

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
