"""Yapisal analiz -- AST-benzeri regex tabanlı kategorizasyon ve isimlendirme.

Babel veya parser gerektirmez. Moduldeki export isimlerini, class isimlerini,
dominant pattern'leri regex ile cikarir ve anlamli dosya adi uretir.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from .result import NamingResult, _sanitize_filename

logger = logging.getLogger(__name__)


# Kategori pattern'leri -- her kategorinin belirleyici string/regex'leri
CATEGORY_PATTERNS: dict[str, list[str]] = {
    "tools": [
        "BashTool", "ReadTool", "WriteTool", "EditTool", "GlobTool",
        "GrepTool", "tool.execute", "toolResult", "ToolUse",
        "ListFilesTool", "SearchTool", "TaskTool",
    ],
    "mcp": [
        "McpServer", "mcp_server", "MCP_SERVER", "createMCPSession",
        "mcpServers", "Model Context Protocol", "McpHub",
        "mcpConnection", "McpTransport",
    ],
    "auth": [
        "authenticate", "authorization", "bearer", "oauth",
        "credential", "session", "login", "permission",
        "apiKey", "x-api-key", "refreshToken", "accessToken",
    ],
    "api": [
        "endpoint", "apiClient", "httpRequest", "baseURL",
        "api.anthropic.com", "apiVersion", "apiResponse",
        "rateLimiter", "retryAfter",
    ],
    "cli": [
        "process.argv", "yargs", "inquirer", "prompt(",
        "parseArgs", "commander", "meow", "cac(",
    ],
    "ui": [
        "render(", "Component", "createElement", "useState",
        "useEffect", "Box", "Text", "Spinner",
    ],
    "config": [
        "loadConfig", "parseConfig", "defaultConfig", "configSchema",
        "preferences", "settingsPath", ".clauderc",
    ],
    "crypto": [
        "encrypt", "decrypt", "cipher", "hmac", "signature",
        "certificate", "publicKey", "privateKey", "createHash",
    ],
    "streams": [
        "Readable", "Writable", "Transform", "pipeline",
        "pipe(", "stream", "Duplex", "PassThrough",
    ],
    "events": [
        "EventEmitter", "emit(", "addEventListener",
        "removeListener", "removeAllListeners",
        "eventTarget", "CustomEvent",
    ],
    "errors": [
        "extends Error", "throw new", "ErrorHandler",
        "errorBoundary", "errorCode", "ApiError",
    ],
    "logging": [
        "logger.", "log.debug", "log.info", "log.warn",
        "log.error", "createLogger", "LogLevel",
    ],
    "server": [
        "createServer", "listen(", "middleware",
        "router", "express()", "fastify",
    ],
    "transport": [
        "stdio", "stdin", "stdout", "stderr",
        "IPC", "socket", "pipe",
    ],
    "permissions": [
        "permission", "allow", "deny", "grant",
        "sandbox", "restricted", "trusted",
    ],
    "markdown": [
        "markdown", "Markdown", "MDX", "mdast",
        "remark", "unified", "heading", "paragraph",
    ],
    "git": [
        "git ", "git.", "commit", "branch",
        "checkout", "merge", "rebase", "diff",
        "repository", "GitError",
    ],
}

# Export name cikartma regex'leri
EXPORT_PATTERNS = [
    # module.exports = { name: ... }
    re.compile(r'(?:module\.)?exports\.(\w+)\s*='),
    # exports.NAME = ...
    re.compile(r'exports\[?"?(\w+)"?\]?\s*='),
    # export { name }
    re.compile(r'export\s*\{\s*(\w+)'),
    # export default class NAME
    re.compile(r'export\s+default\s+class\s+(\w+)'),
    # export default function NAME
    re.compile(r'export\s+default\s+function\s+(\w+)'),
    # export class NAME
    re.compile(r'export\s+class\s+(\w+)'),
    # export function NAME
    re.compile(r'export\s+function\s+(\w+)'),
]

# Class name cikartma
CLASS_PATTERN = re.compile(r'class\s+(\w{3,})\s*(?:extends|\{)')

# Function name cikartma (top-level, buyuk harf baslayanlar)
FUNCTION_PATTERN = re.compile(r'function\s+([A-Z]\w{2,})\s*\(')

# Module header comment'ten isim cikartma (Karadul unpacker yorum ekledi)
HEADER_NAME_PATTERN = re.compile(r'\*\s*Name:\s*(\S+)')
HEADER_TYPE_PATTERN = re.compile(r'\*\s*Type:\s*(\S+)')


class StructuralAnalyzer:
    """AST ve icerik analizi ile modul isimlendirme.

    Islem sirasi:
    1. Header comment'ten mevcut ismi cikar (Karadul unpacker zaten bir isim vermis olabilir)
    2. Export name cikar
    3. Class name cikar
    4. Dominant pattern tespiti (CATEGORY_PATTERNS)
    5. En anlamli isimle NamingResult uret
    """

    def __init__(self, category_patterns: dict[str, list[str]] | None = None) -> None:
        self.category_patterns = category_patterns or CATEGORY_PATTERNS

    def analyze_all(
        self, modules_dir: Path, already_named: set[str]
    ) -> list[NamingResult]:
        """Henuz isimlendirilmemis modulleri analiz et."""
        results: list[NamingResult] = []
        js_files = sorted(modules_dir.glob("*.js"))
        total_skipped = 0
        total_analyzed = 0

        for js_file in js_files:
            module_id = js_file.stem
            if module_id in already_named:
                total_skipped += 1
                continue

            try:
                content = js_file.read_text(errors="replace")
            except Exception:
                logger.debug("Dosya okuma basarisiz, atlaniyor", exc_info=True)
                continue

            total_analyzed += 1
            result = self._analyze_module(content, module_id)
            if result is not None:
                results.append(result)

        logger.info(
            "StructuralAnalyzer: %d analiz, %d atlandı, %d sonuc",
            total_analyzed, total_skipped, len(results),
        )
        return results

    def _analyze_module(self, content: str, module_id: str) -> NamingResult | None:
        """Tek modulu analiz et."""
        # Cok kisa modulleri atla
        if len(content.strip()) < 30:
            return None

        # 1. Header comment'ten isim cikar
        header_name = self._extract_header_name(content)

        # 2. Export isimlerini cikar
        export_names = self._extract_exports(content)

        # 3. Class isimlerini cikar
        class_names = self._extract_classes(content)

        # 4. Function isimlerini cikar
        function_names = self._extract_functions(content)

        # 5. Dominant pattern (kategori) tespiti
        category, category_confidence = self._detect_category(content)

        # Dosya adi belirleme stratejisi:
        # Oncelik: export name > class name > function name > header name > category+module_id
        best_name = None
        confidence = 0.0

        if export_names:
            # En anlamli export adini sec (en uzun, obfuscated olmayan)
            candidates = [n for n in export_names if len(n) > 3 and not self._is_obfuscated(n)]
            if candidates:
                best_name = max(candidates, key=len)
                confidence = 0.7

        if best_name is None and class_names:
            candidates = [n for n in class_names if not self._is_obfuscated(n)]
            if candidates:
                best_name = max(candidates, key=len)
                confidence = 0.65

        if best_name is None and function_names:
            candidates = [n for n in function_names if not self._is_obfuscated(n)]
            if candidates:
                best_name = max(candidates, key=len)
                confidence = 0.55

        if best_name is None and header_name and not self._is_obfuscated(header_name):
            best_name = header_name
            confidence = 0.5

        if best_name is None:
            # Kategori + module_id'den uret
            if category and category_confidence >= 0.3:
                best_name = f"{category}-{module_id}"
                confidence = category_confidence * 0.6
            else:
                # Analiz basarisiz -- bu modulu isimlendiremedik
                return None

        # Kategori yoksa genel "lib" kullan
        if not category:
            category = "lib"

        # CamelCase -> kebab-case
        filename = self._to_kebab_case(best_name)
        filename = _sanitize_filename(filename)

        # Aciklama
        parts = []
        if export_names:
            parts.append(f"exports: {', '.join(export_names[:3])}")
        if class_names:
            parts.append(f"classes: {', '.join(class_names[:3])}")
        description = "; ".join(parts) if parts else f"{category} module"

        return NamingResult(
            module_id=module_id,
            original_file=f"{module_id}.js",
            new_filename=filename,
            category=category,
            description=description[:120],
            confidence=round(confidence, 3),
            source="structural",
            npm_package=None,
        )

    def _extract_header_name(self, content: str) -> str | None:
        """Karadul unpacker header comment'inden modul adini cikar."""
        # Sadece ilk 15 satira bak
        header = "\n".join(content.split("\n")[:15])
        match = HEADER_NAME_PATTERN.search(header)
        if match:
            name = match.group(1)
            # Eger isim module_id ile ayniysa (obfuscated) veya cok kisaysa atla
            if len(name) >= 3:
                return name
        return None

    def _extract_exports(self, content: str) -> list[str]:
        """Export isimlerini cikar."""
        names: list[str] = []
        for pattern in EXPORT_PATTERNS:
            for match in pattern.finditer(content):
                name = match.group(1)
                if name not in names and name not in ("default", "undefined", "__esModule"):
                    names.append(name)
        return names[:10]  # Max 10 export

    def _extract_classes(self, content: str) -> list[str]:
        """Class isimlerini cikar."""
        names: list[str] = []
        for match in CLASS_PATTERN.finditer(content):
            name = match.group(1)
            if name not in names:
                names.append(name)
        return names[:5]

    def _extract_functions(self, content: str) -> list[str]:
        """Buyuk harfle baslayan function isimlerini cikar."""
        names: list[str] = []
        for match in FUNCTION_PATTERN.finditer(content):
            name = match.group(1)
            if name not in names:
                names.append(name)
        return names[:5]

    def _detect_category(self, content: str) -> tuple[str, float]:
        """Dominant pattern'i tespit et ve (kategori, confidence) dondur."""
        best_category = ""
        best_score = 0.0

        for category, patterns in self.category_patterns.items():
            matched = sum(1 for p in patterns if p in content)
            if matched == 0:
                continue
            score = matched / len(patterns)
            if score > best_score:
                best_score = score
                best_category = category

        return best_category, round(best_score, 3)

    @staticmethod
    def _is_obfuscated(name: str) -> bool:
        """Ismin obfuscated olup olmadigini kontrol et."""
        # Tek karakter
        if len(name) <= 2:
            return True
        # Tamamen buyuk harf + rakam (orn: "A3A", "XY2")
        if re.match(r'^[A-Z0-9_]+$', name) and len(name) <= 4:
            return True
        # Tamamen kucuk harf + rakam, 3 karakter (orn: "e9B")
        if re.match(r'^[a-z][0-9][A-Z]$', name):
            return True
        # Underscore ile baslayan kisa isimler
        if name.startswith("_") and len(name) <= 3:
            return True
        return False

    @staticmethod
    def _to_kebab_case(name: str) -> str:
        """CamelCase veya PascalCase'i kebab-case'e cevir."""
        # Underscore'lari tire'ye cevir
        name = name.replace("_", "-")
        # CamelCase ayirma: "MyClassName" -> "My-Class-Name"
        name = re.sub(r'([a-z0-9])([A-Z])', r'\1-\2', name)
        # Ardisik buyuk harfler: "HTTPSConnection" -> "HTTPS-Connection"
        name = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1-\2', name)
        return name.lower()
