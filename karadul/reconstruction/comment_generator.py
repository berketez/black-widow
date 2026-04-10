"""Otomatik yorum ekleme -- fonksiyon basina aciklama.

Fonksiyon adini, parametre isimlerini ve body pattern'lerini
analiz ederek anlamli yorumlar uretir. JSDoc formatinda degil,
basit inline comment olarak calisan bir yorum ureteci.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from karadul.config import Config

logger = logging.getLogger(__name__)

# Fonksiyon body pattern -> yorum
_BODY_PATTERNS: list[tuple[re.Pattern, str]] = [
    # v1.7.x: .* DOTALL -> [^}]* -- try blogu icinde kal, catastrophic backtracking onle
    (re.compile(r"try\s*\{[^}]*\}[^}]*catch"), "Error handling included."),
    (re.compile(r"fetch\s*\(|axios\.|http\."), "Makes HTTP/API call."),
    (re.compile(r"localStorage|sessionStorage"), "Uses browser storage."),
    (re.compile(r"document\.|getElementById|querySelector"), "DOM manipulation."),
    (re.compile(r"addEventListener|\.on\("), "Event listener setup."),
    (re.compile(r"setTimeout|setInterval|requestAnimationFrame"), "Uses timer/async scheduling."),
    (re.compile(r"JSON\.parse|JSON\.stringify"), "JSON serialization/deserialization."),
    (re.compile(r"new\s+RegExp|\.match\(|\.test\(|\.replace\(.*\/"), "Regex processing."),
    (re.compile(r"console\.(log|warn|error|info|debug)"), "Includes logging."),
    (re.compile(r"process\.env"), "Reads environment variables."),
    (re.compile(r"require\(|import\s"), "Module import."),
    (re.compile(r"\.map\(|\.filter\(|\.reduce\(|\.forEach\("), "Array transformation."),
    (re.compile(r"new\s+Promise|\.then\(|await\s"), "Async operation."),
    (re.compile(r"throw\s+new"), "May throw errors."),
    (re.compile(r"fs\.|readFile|writeFile|readdir"), "File system operations."),
    (re.compile(r"crypto\.|createHash|randomBytes"), "Cryptographic operations."),
    (re.compile(r"socket\.|\.emit\(|\.broadcast"), "Socket/realtime communication."),
    # v1.7.x: .* DOTALL -> {0,500} sinirli -- catastrophic backtracking onle
    (re.compile(r"cache|memoize|\.has\([^)]*\)[\s\S]{0,500}\.get\("), "Uses caching."),
    (re.compile(r"validate|sanitize|escape|encode"), "Input validation/sanitization."),
    (re.compile(r"render|createElement|jsx|JSX"), "UI rendering."),
    (re.compile(r"setState|useState|dispatch"), "State management."),
]

# Fonksiyon adi prefix -> aksiyon aciklamasi
_NAME_PREFIXES: dict[str, str] = {
    "get": "Retrieves",
    "set": "Sets",
    "is": "Checks if",
    "has": "Checks whether",
    "can": "Determines if",
    "should": "Decides whether to",
    "will": "Prepares to",
    "create": "Creates",
    "make": "Constructs",
    "build": "Builds",
    "init": "Initializes",
    "setup": "Sets up",
    "handle": "Handles",
    "on": "Responds to",
    "process": "Processes",
    "parse": "Parses",
    "format": "Formats",
    "convert": "Converts",
    "transform": "Transforms",
    "validate": "Validates",
    "check": "Checks",
    "verify": "Verifies",
    "find": "Finds",
    "search": "Searches for",
    "filter": "Filters",
    "sort": "Sorts",
    "update": "Updates",
    "delete": "Deletes",
    "remove": "Removes",
    "add": "Adds",
    "insert": "Inserts",
    "append": "Appends",
    "load": "Loads",
    "save": "Saves",
    "store": "Stores",
    "fetch": "Fetches",
    "send": "Sends",
    "receive": "Receives",
    "emit": "Emits",
    "dispatch": "Dispatches",
    "render": "Renders",
    "display": "Displays",
    "show": "Shows",
    "hide": "Hides",
    "toggle": "Toggles",
    "enable": "Enables",
    "disable": "Disables",
    "register": "Registers",
    "unregister": "Unregisters",
    "subscribe": "Subscribes to",
    "unsubscribe": "Unsubscribes from",
    "start": "Starts",
    "stop": "Stops",
    "reset": "Resets",
    "clear": "Clears",
    "close": "Closes",
    "open": "Opens",
    "connect": "Connects to",
    "disconnect": "Disconnects from",
    "log": "Logs",
    "debug": "Debug output for",
    "error": "Reports error for",
    "warn": "Warns about",
    "notify": "Notifies about",
    "calculate": "Calculates",
    "compute": "Computes",
    "merge": "Merges",
    "split": "Splits",
    "map": "Maps",
    "reduce": "Reduces",
    "extract": "Extracts",
    "apply": "Applies",
    "wrap": "Wraps",
    "unwrap": "Unwraps",
    "encode": "Encodes",
    "decode": "Decodes",
    "encrypt": "Encrypts",
    "decrypt": "Decrypts",
    "serialize": "Serializes",
    "deserialize": "Deserializes",
    "clone": "Clones",
    "copy": "Copies",
}

# Fonksiyon satir baslangic regex
_FUNC_RE = re.compile(
    r"^(\s*)"
    r"(?:export\s+)?(?:async\s+)?"
    r"(?:"
    r"function\s+(\w+)\s*\(|"
    r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\s*)?\(|"
    r"(\w+)\s*(?:\(|:\s*(?:async\s+)?(?:function\s*)?\()"
    r")",
)


class CommentGenerator:
    """Otomatik yorum ekleme -- fonksiyon basina aciklama.

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self.config = config

    def generate(self, input_file: Path, output_file: Path) -> int:
        """Dosyadaki fonksiyonlara yorum ekle.

        Her fonksiyon icin:
        1. Fonksiyon adindan aciklama turet (camelCase parse)
        2. Parametre isimlerinden hint al
        3. Return statement'lardan hint al
        4. Body pattern matching: try/catch -> error handler, fetch -> API call

        Args:
            input_file: Girdi JS dosyasi.
            output_file: Yorum eklenmis cikti dosyasi.

        Returns:
            Eklenen yorum sayisi.
        """
        if not input_file.exists():
            logger.error("Girdi dosyasi bulunamadi: %s", input_file)
            return 0

        try:
            content = input_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.error("Dosya okunamadi: %s", exc)
            return 0

        lines = content.split("\n")
        insertions: list[tuple[int, str]] = []
        comments_added = 0

        for i, line in enumerate(lines):
            # Zaten yorum var mi? (onceki satir yorum ise atla)
            if i > 0 and (
                lines[i - 1].strip().startswith("//")
                or lines[i - 1].strip().endswith("*/")
                or lines[i - 1].strip().startswith("*")
            ):
                continue

            match = _FUNC_RE.match(line)
            if not match:
                continue

            indent = match.group(1)
            func_name = match.group(2) or match.group(3) or match.group(4)

            if not func_name:
                continue

            # Anonim veya cok kisa fonksiyonlar (1-2 satir) icin yorum ekleme
            if func_name in ("<anonymous>", "<arrow>"):
                continue

            # Fonksiyon body'sini topla (basit: sonraki 50 satir)
            body_end = min(i + 50, len(lines))
            body_text = "\n".join(lines[i:body_end])

            # Yorum olustur
            comment = self._generate_comment(func_name, body_text, indent)
            if comment:
                insertions.append((i, comment))
                comments_added += 1

        # Sondan basa ekle
        for line_no, comment_text in reversed(insertions):
            lines.insert(line_no, comment_text)

        try:
            output_file.write_text("\n".join(lines), encoding="utf-8")
        except OSError as exc:
            logger.error("Cikti yazilamadi: %s", exc)
            return 0

        logger.info("Comment generation: %d yorum eklendi", comments_added)
        return comments_added

    @staticmethod
    def _generate_comment(
        func_name: str, body_text: str, indent: str,
    ) -> str:
        """Tek fonksiyon icin yorum olustur.

        Args:
            func_name: Fonksiyon adi.
            body_text: Fonksiyon body'si (ilk 50 satir).
            indent: Indentation.

        Returns:
            Yorum string'i.
        """
        parts: list[str] = []

        # 1. Fonksiyon adindan aciklama
        description = CommentGenerator._name_to_action(func_name)
        if description:
            parts.append(description)

        # 2. Body pattern analizi
        body_notes = []
        for pattern, note in _BODY_PATTERNS:
            if pattern.search(body_text):
                body_notes.append(note)
                if len(body_notes) >= 3:
                    break

        if body_notes:
            parts.extend(body_notes)

        if not parts:
            return ""

        # Tek satirlik yorum
        full_comment = " ".join(parts[:3])
        return f"{indent}// {full_comment}"

    @staticmethod
    def _name_to_action(name: str) -> str:
        """Fonksiyon adini aciklama cumlesine donustur.

        Ornek: getUserProfile -> "Retrieves user profile"
        """
        if not name or name.startswith("<") or name.startswith("_"):
            return ""

        # camelCase'i parcalara ayir
        words = re.sub(r"([A-Z])", r" \1", name).strip().split()
        if not words:
            return ""

        # Ilk kelimeyi prefix olarak bul
        first = words[0].lower()
        prefix_action = _NAME_PREFIXES.get(first)

        if prefix_action and len(words) > 1:
            rest = " ".join(w.lower() for w in words[1:])
            return f"{prefix_action} {rest}."
        else:
            # Prefix bilinmiyorsa basit aciklama
            all_words = " ".join(w.lower() for w in words)
            return f"{all_words.capitalize()}."
