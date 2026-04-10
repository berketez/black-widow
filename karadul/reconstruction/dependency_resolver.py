"""Gercek npm paket bagimliliklarini tespit et.

Mevcut _scan_dependencies (project_builder.py icerisinde) minified kod
parcalarini paket ismi olarak algilayabiliyor. Bu modul daha akilli:
  1. require/import pattern'lerini regex ile bul
  2. Node.js built-in'leri filtrele
  3. Relative import'lari filtrele
  4. Paket ismi validasyonu (gecerli npm ismi mi?)
  5. npm registry'den versiyon dogrulama (opsiyonel)
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from ..config import Config

logger = logging.getLogger(__name__)

# Node.js built-in modulleri
NODE_BUILTINS = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster",
    "console", "constants", "crypto", "dgram", "diagnostics_channel",
    "dns", "domain", "events", "fs", "http", "http2", "https",
    "inspector", "module", "net", "os", "path", "perf_hooks",
    "process", "punycode", "querystring", "readline", "repl",
    "stream", "string_decoder", "sys", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
    # node: prefix
    "node:assert", "node:async_hooks", "node:buffer",
    "node:child_process", "node:cluster", "node:console",
    "node:constants", "node:crypto", "node:dgram",
    "node:diagnostics_channel", "node:dns", "node:domain",
    "node:events", "node:fs", "node:http", "node:http2", "node:https",
    "node:inspector", "node:module", "node:net", "node:os",
    "node:path", "node:perf_hooks", "node:process", "node:punycode",
    "node:querystring", "node:readline", "node:repl",
    "node:stream", "node:string_decoder", "node:sys",
    "node:timers", "node:tls", "node:trace_events", "node:tty",
    "node:url", "node:util", "node:v8", "node:vm", "node:wasi",
    "node:worker_threads", "node:zlib",
    # Sub-path
    "fs/promises", "path/posix", "path/win32", "dns/promises",
    "readline/promises", "stream/promises", "stream/web",
    "stream/consumers", "timers/promises", "util/types",
    "node:fs/promises", "node:path/posix", "node:path/win32",
    "node:dns/promises", "node:readline/promises",
    "node:stream/promises", "node:stream/web",
    "node:stream/consumers", "node:timers/promises",
    "node:util/types",
})

# Gecerli npm paket ismi regex (npm naming rules)
# - Kucuk harf, tire, alt cizgi, nokta
# - Scoped: @scope/package
# - Uzunluk: 1-214 karakter
_VALID_PKG_NAME = re.compile(
    r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$",
    re.IGNORECASE,
)

# require/import tespiti
_REQUIRE_RE = re.compile(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)')
_IMPORT_RE = re.compile(r'(?:import|from)\s+["\']([^"\']+)["\']')
_DYNAMIC_IMPORT_RE = re.compile(r'import\s*\(\s*["\']([^"\']+)["\']\s*\)')


class DependencyResolver:
    """Gercek npm paket bagimlilikdarini tespit et.

    ProjectBuilder._scan_dependencies'in yerine gecen daha guvenilir versiyon.

    Args:
        config: Merkezi konfigurasyon.
        verify_npm: npm registry'den versiyon dogrulama yapilsin mi.
        npm_timeout: npm view komutu icin zaman asimi (saniye).
    """

    def __init__(
        self,
        config: Config,
        verify_npm: bool = False,
        npm_timeout: int = 10,
    ) -> None:
        self.config = config
        self.verify_npm = verify_npm
        self.npm_timeout = npm_timeout
        self._npm_cache: dict[str, str | None] = {}

    def resolve(self, source_dir: Path) -> dict[str, str]:
        """Dizindeki tum JS dosyalarindan gercek npm paketlerini tespit et.

        Iki strateji:
        1. require/import statement'lardan paket isimlerini cikar (klasik)
        2. Embedded dependency detection -- bundle icindeki paket isim/versiyon
           referanslarini bul (esbuild gibi her seyi embed eden bundler'lar icin)

        Args:
            source_dir: JS dosyalarinin bulundugu dizin.

        Returns:
            Paket adi -> versiyon eslesmesi.
        """
        raw_modules: set[str] = set()
        all_content = []  # Embedded detection icin

        # Tum JS dosyalarini tara
        for js_file in source_dir.rglob("*.js"):
            try:
                content = js_file.read_text(encoding="utf-8", errors="replace")
                self._extract_modules(content, raw_modules)
                all_content.append(content)
            except OSError:
                continue

        # Filtrele ve dogrula
        deps: dict[str, str] = {}

        for module_name in sorted(raw_modules):
            pkg = self._resolve_package_name(module_name)
            if not pkg:
                continue
            if pkg in deps:
                continue

            if self.verify_npm:
                version = self._npm_lookup(pkg)
                if version:
                    deps[pkg] = version
            else:
                deps[pkg] = "latest"

        # Embedded dependency detection
        full_text = "\n".join(all_content)
        embedded = self._detect_embedded_packages(full_text)
        for pkg, ver in embedded.items():
            if pkg not in deps:
                deps[pkg] = ver

        logger.info(
            "Dependency resolver: %d require + %d embedded = %d paket",
            len(raw_modules), len(embedded), len(deps),
        )
        return deps

    def resolve_from_content(self, content: str) -> dict[str, str]:
        """Tek bir JS iceriginden bagimliliklari tespit et.

        Args:
            content: JS kaynak kodu.

        Returns:
            Paket adi -> versiyon eslesmesi.
        """
        raw_modules: set[str] = set()
        self._extract_modules(content, raw_modules)

        deps: dict[str, str] = {}
        for module_name in sorted(raw_modules):
            pkg = self._resolve_package_name(module_name)
            if pkg and pkg not in deps:
                if self.verify_npm:
                    version = self._npm_lookup(pkg)
                    if version:
                        deps[pkg] = version
                else:
                    deps[pkg] = "latest"

        return deps

    @staticmethod
    def _extract_modules(content: str, modules: set[str]) -> None:
        """JS icerigindeki require/import module isimlerini cikar."""
        for pattern in (_REQUIRE_RE, _IMPORT_RE, _DYNAMIC_IMPORT_RE):
            for match in pattern.finditer(content):
                modules.add(match.group(1))

    def _resolve_package_name(self, module_name: str) -> Optional[str]:
        """Ham module isminden npm paket ismini cikar, gecersizse None dondur.

        Filtreler:
        1. Relative import -> None
        2. Node built-in -> None
        3. Gecersiz karakter -> None
        4. Cok uzun -> None
        5. Minified kod parcasi -> None
        """
        if not module_name:
            return None

        # Relative import
        if module_name.startswith(".") or module_name.startswith("/"):
            return None

        # Node built-in
        if module_name in NODE_BUILTINS:
            return None
        if module_name.startswith("node:"):
            return None

        # Built-in sub-path (fs/promises gibi)
        base = module_name.split("/")[0]
        if base in NODE_BUILTINS:
            return None

        # Paket ismini cikar
        if module_name.startswith("@"):
            # Scoped package: @scope/package
            parts = module_name.split("/")
            if len(parts) < 2:
                return None
            pkg = f"{parts[0]}/{parts[1]}"
        else:
            # Normal: ilk / oncesi
            pkg = module_name.split("/")[0]

        # --- Validasyon ---

        # Bos
        if not pkg:
            return None

        # Uzunluk kontrolu (npm max 214, ama makul isim 50'den kisa)
        if len(pkg) > 60:
            return None

        # Bosluk veya newline iceriyor (minified kod parcasi)
        if " " in pkg or "\n" in pkg or "\t" in pkg or "\r" in pkg:
            return None

        # Noktali virgul, parantez, kume parantez, esittir (kod parcasi)
        if any(c in pkg for c in ";(){}=<>!&|?:,+*%'\"\\"):
            return None

        # npm paket ismi regex kontrolu
        if not _VALID_PKG_NAME.match(pkg):
            return None

        # Sadece rakamlardan olusan isim (muhtemelen module ID)
        if pkg.isdigit():
            return None

        # Cok kisa ve muhtemelen anlamsiz (tek karakter degisken adi)
        if len(pkg) == 1:
            return None

        return pkg

    @staticmethod
    def _detect_embedded_packages(content: str) -> dict[str, str]:
        """Bundle iceriginden embed edilmis npm paketlerini tespit et.

        esbuild gibi bundler'lar tum dependency'leri tek dosyaya gomuyor.
        Bu durumda require/import statement'lari yok, ama paket isimleri ve
        versiyonlari string literal olarak bulunabilir.

        Pattern'ler:
        - @scope/package-name X.Y.Z (yorum veya string icinde)
        - "name": "package-name", "version": "X.Y.Z" (package.json embed)
        - /* package-name@X.Y.Z */ (banner yorumlari)
        - https://github.com/org/repo (GitHub URL'leri)
        """
        embedded: dict[str, str] = {}

        # Pattern 1: @scope/package X.Y.Z veya package-name X.Y.Z (banner yorum)
        banner_re = re.compile(
            r"[/\*!]\s*(@[\w.-]+/[\w.-]+|[\w][\w.-]+)\s+"
            r"(\d+\.\d+\.\d+(?:-[\w.]+)?)"
        )
        for match in banner_re.finditer(content):
            pkg = match.group(1)
            ver = match.group(2)
            # Sadece gecerli npm isimleri
            if _VALID_PKG_NAME.match(pkg) and pkg not in embedded:
                # Node built-in'leri atla
                base = pkg.split("/")[0].lstrip("@")
                if base not in NODE_BUILTINS:
                    embedded[pkg] = f"^{ver}"

        # Pattern 2: GitHub URL'lerden paket tespiti
        github_re = re.compile(
            r"https?://github\.com/([\w.-]+)/([\w.-]+)"
        )
        seen_repos: set[str] = set()
        for match in github_re.finditer(content):
            org = match.group(1)
            repo = match.group(2)
            repo_key = f"{org}/{repo}"
            if repo_key in seen_repos:
                continue
            seen_repos.add(repo_key)
            # Bilinen org -> npm paket eslestirmeleri
            known_orgs = {
                "getsentry": "@sentry/node",
                "grpc": "@grpc/grpc-js",
                "openai": "openai",
                "anthropics": "@anthropic-ai/sdk",
            }
            if org in known_orgs:
                pkg = known_orgs[org]
                if pkg not in embedded:
                    embedded[pkg] = "latest"

        return embedded

    def _npm_lookup(self, package_name: str) -> Optional[str]:
        """npm registry'den paketin son versiyonunu al.

        Args:
            package_name: npm paket adi.

        Returns:
            Versiyon string'i veya None (bulunamazsa).
        """
        # Cache kontrolu
        if package_name in self._npm_cache:
            return self._npm_cache[package_name]

        try:
            result = subprocess.run(
                [str(self.config.tools.npm), "view", package_name, "version"],
                capture_output=True,
                text=True,
                timeout=self.npm_timeout,
            )

            if result.returncode == 0 and result.stdout.strip():
                version = f"^{result.stdout.strip()}"
                self._npm_cache[package_name] = version
                return version
            else:
                self._npm_cache[package_name] = None
                return None

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            self._npm_cache[package_name] = None
            return None
