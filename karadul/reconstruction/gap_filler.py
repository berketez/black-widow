"""Statik + dinamik analiz sonuclarini birlestir, eksikleri tamamla.

Statik analizde tespit edilen import/export/fonksiyon bilgilerini
dinamik analiz sonuclariyla (Frida trace) karsilastirir, dead code
tespiti yapar ve eksik import'lari tamamlar.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import Config
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)


@dataclass
class GapFillResult:
    """Gap filling sonucu.

    Attributes:
        success: Islem basarili mi.
        dead_code_functions: Statik'te var, dinamik'te cagrilmamis fonksiyonlar.
        missing_imports: Dinamik'te require var, statik'te yok.
        api_endpoints: Tespit edilen API endpoint'leri.
        env_variables: Tespit edilen environment variable'lar.
        merged_imports: Birlestirilmis import listesi.
        stats: Istatistikler.
        errors: Hatalar.
    """

    success: bool
    dead_code_functions: list[str] = field(default_factory=list)
    missing_imports: list[str] = field(default_factory=list)
    api_endpoints: list[dict[str, str]] = field(default_factory=list)
    env_variables: list[str] = field(default_factory=list)
    merged_imports: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# URL tespiti regex
_URL_PATTERN = re.compile(
    r'["\']'
    r"(https?://[^\s\"']+)"
    r'["\']',
)

# Relative API path tespiti
_API_PATH_PATTERN = re.compile(
    r'["\']'
    r"(/api/[^\s\"']+|/v[0-9]+/[^\s\"']+)"
    r'["\']',
)

# process.env pattern
_ENV_VAR_PATTERN = re.compile(
    r"process\.env\.(\w+)|"
    r"process\.env\[[\"\'](\w+)[\"\']\]",
)


class GapFiller:
    """Statik + dinamik analiz sonuclarini birlestir, eksikleri tamamla.

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self.config = config

    def fill(self, workspace: Workspace) -> GapFillResult:
        """Analiz bosuklarini doldur.

        1. Statik analizde bulunan import'lar vs dinamik'te yakalanan require() eslestir
        2. Dead code tespiti: statik'te var, dinamik'te cagrilmamis
        3. Eksik import tamamlama: dinamik'te require('X') var, statik'te yok -> ekle
        4. API endpoint tespiti: dinamik'te yakalanan URL'ler -> api/endpoints.json
        5. Environment variable tespiti: process.env.X -> env_variables listesi

        Args:
            workspace: Calisma dizini.

        Returns:
            GapFillResult: Sonuc.
        """
        errors: list[str] = []

        # Statik analiz sonuclarini oku
        static_data = workspace.load_json("static", "ast-analysis")
        static_imports = self._extract_static_imports(static_data)
        static_functions = self._extract_static_functions(static_data)

        # Dinamik analiz sonuclarini oku
        dynamic_data = workspace.load_json("dynamic", "trace_report")
        dynamic_calls = self._extract_dynamic_calls(dynamic_data)
        dynamic_modules = self._extract_dynamic_modules(dynamic_data)

        # 1. Dead code tespiti
        dead_code = self._detect_dead_code(static_functions, dynamic_calls)

        # 2. Missing imports
        missing_imports = self._detect_missing_imports(
            static_imports, dynamic_modules,
        )

        # 3. Merged imports
        merged = sorted(set(static_imports) | set(dynamic_modules))

        # 4. API endpoint tespiti
        api_endpoints = self._detect_api_endpoints(workspace)

        # 5. Environment variable tespiti
        env_variables = self._detect_env_variables(workspace)

        # Sonuclari workspace'e kaydet
        try:
            reconstructed_dir = workspace.get_stage_dir("reconstructed")

            # Gap analysis raporu
            report = {
                "dead_code_functions": dead_code,
                "missing_imports": missing_imports,
                "api_endpoints": api_endpoints,
                "env_variables": env_variables,
                "merged_imports": merged,
                "stats": {
                    "static_imports": len(static_imports),
                    "dynamic_modules": len(dynamic_modules),
                    "dead_code_count": len(dead_code),
                    "missing_import_count": len(missing_imports),
                    "api_endpoint_count": len(api_endpoints),
                    "env_variable_count": len(env_variables),
                },
            }
            workspace.save_json("reconstructed", "gap-analysis", report)

            # API endpoints ayri dosya
            if api_endpoints:
                workspace.save_json(
                    "reconstructed", "api-endpoints", {"endpoints": api_endpoints},
                )

        except OSError as exc:
            errors.append(f"Gap analysis kaydedilemedi: {exc}")

        stats = {
            "static_imports": len(static_imports),
            "static_functions": len(static_functions),
            "dynamic_calls": len(dynamic_calls),
            "dynamic_modules": len(dynamic_modules),
            "dead_code": len(dead_code),
            "missing_imports": len(missing_imports),
            "api_endpoints": len(api_endpoints),
            "env_variables": len(env_variables),
        }

        logger.info(
            "Gap analysis: %d dead code, %d missing import, %d API endpoint, %d env var",
            len(dead_code),
            len(missing_imports),
            len(api_endpoints),
            len(env_variables),
        )

        return GapFillResult(
            success=True,
            dead_code_functions=dead_code,
            missing_imports=missing_imports,
            api_endpoints=api_endpoints,
            env_variables=env_variables,
            merged_imports=merged,
            stats=stats,
            errors=errors,
        )

    @staticmethod
    def _extract_static_imports(data: dict | None) -> list[str]:
        """Statik analiz sonucundan import listesi cikar."""
        if not data:
            return []
        imports = data.get("imports", [])
        sources: list[str] = []
        for imp in imports:
            source = imp.get("source", "")
            if source and source not in sources:
                sources.append(source)
        return sources

    @staticmethod
    def _extract_static_functions(data: dict | None) -> list[str]:
        """Statik analiz sonucundan fonksiyon isim listesi cikar."""
        if not data:
            return []
        functions = data.get("functions", [])
        return [
            f.get("name", "")
            for f in functions
            if f.get("name") and f["name"] not in ("<anonymous>", "<arrow>")
        ]

    @staticmethod
    def _extract_dynamic_calls(data: dict | None) -> list[str]:
        """Dinamik analiz sonucundan cagirilan fonksiyon listesi cikar."""
        if not data:
            return []
        api_calls = data.get("api_calls", [])
        calls: list[str] = []
        for call in api_calls:
            name = call.get("name", "") if isinstance(call, dict) else str(call)
            if name and name not in calls:
                calls.append(name)
        return calls

    @staticmethod
    def _extract_dynamic_modules(data: dict | None) -> list[str]:
        """Dinamik analiz sonucundan yuklenen modul listesi cikar."""
        if not data:
            return []
        modules = data.get("unique_modules", [])
        return [str(m) for m in modules if m]

    @staticmethod
    def _detect_dead_code(
        static_functions: list[str],
        dynamic_calls: list[str],
    ) -> list[str]:
        """Dead code tespiti: statik'te tanimli, dinamik'te cagrilmamis fonksiyonlar.

        Not: Dinamik analiz verisi yoksa bos liste doner (false positive onleme).
        """
        if not dynamic_calls:
            # Dinamik analiz yoksa dead code tespit etme
            return []

        dynamic_set = set(dynamic_calls)
        dead: list[str] = []

        for func_name in static_functions:
            if func_name not in dynamic_set:
                dead.append(func_name)

        return dead

    @staticmethod
    def _detect_missing_imports(
        static_imports: list[str],
        dynamic_modules: list[str],
    ) -> list[str]:
        """Dinamik'te yuklenen ama statik'te bildirilmemis modulleri bul."""
        static_set = set(static_imports)
        missing: list[str] = []

        for mod in dynamic_modules:
            if mod not in static_set:
                missing.append(mod)

        return missing

    def _detect_api_endpoints(self, workspace: Workspace) -> list[dict[str, str]]:
        """Tum workspace dosyalarindaki API endpoint URL'lerini tespit et."""
        endpoints: list[dict[str, str]] = []
        seen_urls: set[str] = set()

        # Dinamik analiz mesajlarini tara
        raw_messages = workspace.load_json("dynamic", "raw_messages")
        if raw_messages:
            messages = raw_messages.get("messages", [])
            for msg in messages:
                text = json.dumps(msg) if isinstance(msg, dict) else str(msg)
                self._extract_urls(text, endpoints, seen_urls)

        # Deobfuscated dosyalari tara
        deob_dir = workspace.get_stage_dir("deobfuscated")
        if deob_dir.exists():
            for js_file in deob_dir.rglob("*.js"):
                try:
                    content = js_file.read_text(
                        encoding="utf-8", errors="replace",
                    )
                    self._extract_urls(content, endpoints, seen_urls)
                except OSError:
                    pass

        # Statik analiz string'lerini tara
        strings_data = workspace.load_json("static", "strings")
        if strings_data:
            for s in strings_data.get("strings", []):
                self._extract_urls(str(s), endpoints, seen_urls)

        return endpoints

    @staticmethod
    def _extract_urls(
        text: str,
        endpoints: list[dict[str, str]],
        seen: set[str],
    ) -> None:
        """Text'ten URL'leri cikar ve endpoints listesine ekle."""
        # Tam URL'ler
        for match in _URL_PATTERN.finditer(text):
            url = match.group(1)
            if url not in seen:
                seen.add(url)
                endpoints.append({"url": url, "type": "absolute"})

        # Relative API path'ler
        for match in _API_PATH_PATTERN.finditer(text):
            path = match.group(1)
            if path not in seen:
                seen.add(path)
                endpoints.append({"url": path, "type": "relative"})

    def _detect_env_variables(self, workspace: Workspace) -> list[str]:
        """Tum workspace dosyalarindaki process.env referanslarini bul."""
        env_vars: set[str] = set()

        # Deobfuscated dosyalari tara
        deob_dir = workspace.get_stage_dir("deobfuscated")
        if deob_dir.exists():
            for js_file in deob_dir.rglob("*.js"):
                try:
                    content = js_file.read_text(
                        encoding="utf-8", errors="replace",
                    )
                    for match in _ENV_VAR_PATTERN.finditer(content):
                        var_name = match.group(1) or match.group(2)
                        if var_name:
                            env_vars.add(var_name)
                except OSError:
                    pass

        # Statik analiz string'lerinde process.env ara
        strings_data = workspace.load_json("static", "strings")
        if strings_data:
            for s in strings_data.get("strings", []):
                for match in _ENV_VAR_PATTERN.finditer(str(s)):
                    var_name = match.group(1) or match.group(2)
                    if var_name:
                        env_vars.add(var_name)

        # Raw dosyalari da tara
        raw_dir = workspace.get_stage_dir("raw")
        if raw_dir.exists():
            for js_file in raw_dir.glob("*.js"):
                try:
                    content = js_file.read_text(
                        encoding="utf-8", errors="replace",
                    )
                    for match in _ENV_VAR_PATTERN.finditer(content):
                        var_name = match.group(1) or match.group(2)
                        if var_name:
                            env_vars.add(var_name)
                except OSError:
                    pass

        return sorted(env_vars)
