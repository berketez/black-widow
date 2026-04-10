"""LLM ile modul isimlendirme -- Codex CLI, Claude API veya fallback heuristic.

Kalan modulleri (npm + structural ile isimlendirilememisleri) LLM'e gonderir.
Batch halinde isler, JSON parse eder, NamingResult uretir.

Fallback: LLM yoksa basit heuristic (icerikteki en sik string'lerden isim turetme).
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .result import NamingResult, _sanitize_filename

logger = logging.getLogger(__name__)

CODEX_PATH = Path("/opt/homebrew/bin/codex")

# LLM'e gonderilecek prompt sablonu
NAMING_PROMPT_TEMPLATE = """You are analyzing deobfuscated JavaScript modules from Claude Code CLI (Anthropic's AI-powered terminal tool).

For each module below, provide:
1. filename: descriptive kebab-case name (e.g., "mcp-session-handler.js")
2. category: one of [api, auth, cli, components, config, core, errors, events, git, hooks, lib, logging, markdown, mcp, permissions, server, streams, tools, transport, ui, utils, vendor]
3. description: one-line description

Return ONLY valid JSON array, no other text:
[{{"id": "MODULE_ID", "filename": "NAME.js", "category": "CATEGORY", "description": "DESC"}}]

{modules_text}"""


class LLMNamer:
    """LLM tabanli modul isimlendirici.

    Oncelik sirasi:
    1. Codex CLI (/opt/homebrew/bin/codex) -- bilgisayarda kuruluysa
    2. Fallback heuristic -- LLM yoksa basit icerik analizi
    """

    BATCH_SIZE = 15  # Modul / istek (prompt uzunlugunu kontrol altinda tutar)

    def __init__(self, use_codex: bool = True, timeout: int = 120) -> None:
        self.use_codex = use_codex and CODEX_PATH.exists()
        self.timeout = timeout

    def name_modules(
        self,
        modules: list[tuple[str, str]],
        context: dict[str, Any] | None = None,
    ) -> list[NamingResult]:
        """Modulleri isimlendir.

        Args:
            modules: [(module_id, content), ...] listesi.
            context: Zaten isimlendirilmis moduller (komsu bilgisi).

        Returns:
            NamingResult listesi.
        """
        if not modules:
            return []

        results: list[NamingResult] = []
        batches = [
            modules[i : i + self.BATCH_SIZE]
            for i in range(0, len(modules), self.BATCH_SIZE)
        ]

        logger.info(
            "LLMNamer: %d modul, %d batch (%s)",
            len(modules),
            len(batches),
            "codex" if self.use_codex else "heuristic",
        )

        for batch_idx, batch in enumerate(batches):
            try:
                if self.use_codex:
                    batch_results = self._process_batch_codex(batch, context)
                else:
                    batch_results = self._process_batch_heuristic(batch)
                results.extend(batch_results)
            except Exception as exc:
                logger.warning(
                    "Batch %d/%d hatasi: %s -- heuristic fallback",
                    batch_idx + 1, len(batches), exc,
                )
                # Hata durumunda heuristic fallback
                fallback = self._process_batch_heuristic(batch)
                results.extend(fallback)

            if (batch_idx + 1) % 10 == 0:
                logger.info(
                    "LLMNamer: %d/%d batch tamamlandi, %d sonuc",
                    batch_idx + 1, len(batches), len(results),
                )

        logger.info("LLMNamer tamamlandi: %d sonuc", len(results))
        return results

    def _process_batch_codex(
        self,
        batch: list[tuple[str, str]],
        context: dict[str, Any] | None,
    ) -> list[NamingResult]:
        """Tek batch'i Codex CLI ile isle."""
        prompt = self._build_prompt(batch, context)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [
                    str(CODEX_PATH),
                    "exec",
                    prompt,
                    "-o",
                    tmp_path,
                    "--skip-git-repo-check",
                    "-s",
                    "read-only",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode != 0:
                logger.warning("Codex hata kodu %d: %s", result.returncode, result.stderr[:200])
                return self._process_batch_heuristic(batch)

            # Codex ciktisini oku
            output_path = Path(tmp_path)
            if not output_path.exists():
                return self._process_batch_heuristic(batch)

            output = output_path.read_text()
            return self._parse_llm_response(output, batch)

        except subprocess.TimeoutExpired:
            logger.warning("Codex timeout (%ds)", self.timeout)
            return self._process_batch_heuristic(batch)
        except Exception as exc:
            logger.warning("Codex exception: %s", exc)
            return self._process_batch_heuristic(batch)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _build_prompt(
        self,
        batch: list[tuple[str, str]],
        context: dict[str, Any] | None,
    ) -> str:
        """Naming prompt olustur."""
        modules_text = ""
        for module_id, content in batch:
            # Max 80 satir goster
            lines = content.split("\n")[:80]
            truncated = "\n".join(lines)
            modules_text += f"\n--- Module {module_id} ---\n{truncated}\n"

        return NAMING_PROMPT_TEMPLATE.format(modules_text=modules_text)

    def _parse_llm_response(
        self, output: str, batch: list[tuple[str, str]]
    ) -> list[NamingResult]:
        """LLM ciktisini parse et."""
        # JSON array bul
        json_match = re.search(r'\[[\s\S]*?\]', output)
        if not json_match:
            logger.warning("LLM ciktisinda JSON bulunamadi")
            return self._process_batch_heuristic(batch)

        try:
            items = json.loads(json_match.group())
        except json.JSONDecodeError:
            logger.warning("LLM JSON parse hatasi")
            return self._process_batch_heuristic(batch)

        # module_id -> content map
        batch_map = {mid: content for mid, content in batch}
        results: list[NamingResult] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            mid = item.get("id", "")
            if mid not in batch_map:
                continue

            filename = item.get("filename", f"{mid}.js")
            category = item.get("category", "lib")
            description = item.get("description", "LLM-named module")

            filename = _sanitize_filename(filename)

            results.append(
                NamingResult(
                    module_id=mid,
                    original_file=f"{mid}.js",
                    new_filename=filename,
                    category=category,
                    description=description[:120],
                    confidence=0.45,  # LLM isimlendirmesi orta confidence
                    source="llm_assisted",
                    npm_package=None,
                )
            )

        return results

    def _process_batch_heuristic(
        self, batch: list[tuple[str, str]]
    ) -> list[NamingResult]:
        """LLM olmadan basit heuristic ile isimlendirme.

        Strateji:
        - Icerikten anlamli string'ler cikar
        - En sik ve en anlamli olani dosya adi yap
        - Basit kategori tespiti
        """
        results: list[NamingResult] = []
        for module_id, content in batch:
            result = self._heuristic_name(module_id, content)
            if result is not None:
                results.append(result)
        return results

    def _heuristic_name(self, module_id: str, content: str) -> NamingResult | None:
        """Basit heuristic ile tek modulu isimlendir."""
        if len(content.strip()) < 30:
            return None

        # String literal'leri cikar
        string_lits = re.findall(r'"([a-zA-Z][\w./-]{3,40})"', content)
        string_lits += re.findall(r"'([a-zA-Z][\w./-]{3,40})'", content)

        # Anlamli isimleri filtrele
        meaningful = []
        noise = {
            "undefined", "default", "object", "function", "string",
            "number", "boolean", "value", "true", "false", "null",
            "prototype", "constructor", "length", "name", "type",
            "__esModule", "enumerable", "configurable", "writable",
        }
        for s in string_lits:
            if s.lower() in noise:
                continue
            if len(s) >= 4 and not s.startswith("_"):
                meaningful.append(s)

        # En sik geceni bul
        from collections import Counter
        counts = Counter(meaningful)
        if not counts:
            # Son care: module_id'yi kullan
            return NamingResult(
                module_id=module_id,
                original_file=f"{module_id}.js",
                new_filename=_sanitize_filename(f"module-{module_id}"),
                category="lib",
                description="Unknown module (no distinctive strings)",
                confidence=0.15,
                source="heuristic",
                npm_package=None,
            )

        # En cok gecen anlamli string
        top_string = counts.most_common(1)[0][0]
        # Path ise son kismi al
        if "/" in top_string:
            top_string = top_string.split("/")[-1]

        filename = _sanitize_filename(top_string)

        # Basit kategori tahmini
        category = "lib"
        content_lower = content.lower()
        if "error" in content_lower and "throw" in content_lower:
            category = "errors"
        elif "stream" in content_lower or "readable" in content_lower:
            category = "streams"
        elif "event" in content_lower and "emit" in content_lower:
            category = "events"
        elif "http" in content_lower and "request" in content_lower:
            category = "api"
        elif "crypto" in content_lower or "cipher" in content_lower:
            category = "crypto"
        elif "logger" in content_lower or "log(" in content_lower:
            category = "logging"
        elif "test" in content_lower and ("assert" in content_lower or "expect" in content_lower):
            category = "test"

        return NamingResult(
            module_id=module_id,
            original_file=f"{module_id}.js",
            new_filename=filename,
            category=category,
            description=f"Heuristic: dominant string '{top_string}'",
            confidence=0.25,
            source="heuristic",
            npm_package=None,
        )
