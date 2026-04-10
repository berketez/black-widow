"""Claude CLI ile LLM-assisted variable naming.

Context analyzer'in scope-aware ciktisindaki dusuk-confidence degiskenleri
Claude CLI'a (`claude -p`) gonderir, batch halinde isimlendirir.

Pipeline:
1. Context JSON'dan dusuk-confidence degiskenleri cikar
2. BATCH_SIZE'lik gruplara bol
3. Her batch icin `claude -p` ile prompt gonder
4. Yaniti JSON olarak parse et
5. Sonuclari birlestir, mapping dondur

Kullanim:
    from karadul.reconstruction.naming.llm_naming import ClaudeLLMNamer
    namer = ClaudeLLMNamer(config)
    result = namer.name_variables(context_json_path, source_file)
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import Config

logger = logging.getLogger(__name__)

# Claude CLI path
CLAUDE_CLI_PATH = Path("/opt/homebrew/bin/claude")

# ---------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------

NAMING_PROMPT = """You are analyzing deobfuscated JavaScript variables.
For each variable below, suggest a meaningful name based on the context.

Return ONLY valid JSON: {{"renames": [{{"id": "scope::varname", "new_name": "suggestedName", "reason": "brief reason"}}]}}

Variables to name:

{variables_context}"""

VARIABLE_CONTEXT_TEMPLATE = """
--- Variable: {old_name} (scope: {scope_id}) ---
Declaration: {declaration_type}
Used {reference_count} times
APIs used with: {api_calls}
Properties accessed: {properties}
Data flow: {data_flow}
Current best guess: {current_name} (confidence: {confidence})
Code snippet:
```js
{code_snippet}
```
"""


# ---------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------

@dataclass
class LLMNamingResult:
    """Claude LLM variable naming sonucu.

    Attributes:
        success: Islem basarili mi.
        total_named: LLM tarafindan isimlendirilen degisken sayisi.
        total_batches: Toplam batch sayisi.
        failed_batches: Basarisiz batch sayisi.
        mappings: {scope_id: {old_name: new_name}} eslesmesi.
        reasons: {scope_id::old_name: reason} aciklama eslesmesi.
        duration_seconds: Toplam sure.
        errors: Hata mesajlari.
        model_used: Kullanilan model.
    """

    success: bool = False
    total_named: int = 0
    total_batches: int = 0
    failed_batches: int = 0
    mappings: dict[str, dict[str, str]] = field(default_factory=dict)
    reasons: dict[str, str] = field(default_factory=dict)
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    model_used: str = ""


# ---------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------

class ClaudeLLMNamer:
    """Claude CLI ile LLM-assisted variable naming.

    Context analyzer'in scope-aware ciktisindaki dusuk-confidence
    degiskenleri Claude'a gonderip anlamli isimler alir.

    Args:
        config: Merkezi konfigurasyon.
        model: Claude model adi. Varsayilan Sonnet (ucuz).
        batch_size: Batch basina degisken sayisi.
        max_code_lines: Degisken basina gosterilecek max kod satiri.
        timeout: Batch basina timeout (saniye).
        min_confidence: Bu esik altindaki degiskenler LLM'e gonderilir.
        min_references: Minimum referans sayisi (cok az kullanilan degisken icin LLM'e gerek yok).
    """

    BATCH_SIZE = 15
    MAX_CODE_LINES = 40
    # Model alias kullan -- tam model ismi (claude-sonnet-4-20250514) CLAUDE.md
    # system prompt'u ile birlikte context limitini asiyor.
    # "sonnet" alias'i son stable Sonnet'e yonlendirir.
    DEFAULT_MODEL = "sonnet"
    DEFAULT_TIMEOUT = 60

    def __init__(
        self,
        config: Config,
        model: str | None = None,
        batch_size: int | None = None,
        max_code_lines: int | None = None,
        timeout: int | None = None,
        min_confidence: float = 0.5,
        min_references: int = 2,
    ) -> None:
        self.config = config
        self.model = model or self.DEFAULT_MODEL
        self.batch_size = batch_size or self.BATCH_SIZE
        self.max_code_lines = max_code_lines or self.MAX_CODE_LINES
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.min_confidence = min_confidence
        self.min_references = min_references

        # Claude CLI varligini kontrol et
        self._cli_available = CLAUDE_CLI_PATH.exists()
        if not self._cli_available:
            logger.warning(
                "Claude CLI bulunamadi: %s -- LLM naming devre disi",
                CLAUDE_CLI_PATH,
            )

    @property
    def is_available(self) -> bool:
        """Claude CLI kullanilabilir mi."""
        return self._cli_available

    def name_variables(
        self,
        context_json: Path,
        source_file: Path,
    ) -> LLMNamingResult:
        """Context JSON'dan dusuk-confidence degiskenleri LLM ile isimlendir.

        Args:
            context_json: context-analyzer.mjs ciktisi (JSON dosyasi).
            source_file: Orijinal JS kaynak dosyasi (kod snippet'leri icin).

        Returns:
            LLMNamingResult: Isimlendirme sonucu.
        """
        t0 = time.monotonic()
        result = LLMNamingResult(model_used=self.model)

        if not self._cli_available:
            result.errors.append("Claude CLI bulunamadi")
            result.duration_seconds = time.monotonic() - t0
            return result

        # 1. Context JSON'u oku
        try:
            context_data = json.loads(context_json.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            result.errors.append(f"Context JSON okunamadi: {exc}")
            result.duration_seconds = time.monotonic() - t0
            return result

        # 2. Kaynak kodu oku
        try:
            source_lines = source_file.read_text(errors="replace").splitlines()
        except OSError as exc:
            result.errors.append(f"Kaynak dosya okunamadi: {exc}")
            result.duration_seconds = time.monotonic() - t0
            return result

        # 3. Dusuk-confidence degiskenleri filtrele
        variables = self._extract_low_confidence_vars(context_data)
        if not variables:
            logger.info("LLM naming: dusuk-confidence degisken yok, atlaniyor")
            result.success = True
            result.duration_seconds = time.monotonic() - t0
            return result

        logger.info(
            "LLM naming: %d dusuk-confidence degisken, model=%s",
            len(variables), self.model,
        )

        # 4. Batch'lere bol
        batches = [
            variables[i : i + self.batch_size]
            for i in range(0, len(variables), self.batch_size)
        ]
        result.total_batches = len(batches)

        # 5. Her batch icin Claude CLI cagir
        for batch_idx, batch in enumerate(batches):
            try:
                prompt = self._prepare_batch(batch, source_lines)
                response = self._call_claude(prompt)
                batch_mappings = self._parse_response(response)

                # Sonuclari birlestir
                for item in batch_mappings:
                    scope_var_id = item.get("id", "")
                    new_name = item.get("new_name", "")
                    reason = item.get("reason", "")

                    if not scope_var_id or not new_name:
                        continue

                    # scope::varname formatindan ayir
                    parts = scope_var_id.split("::", 1)
                    if len(parts) == 2:
                        scope_id, old_name = parts
                    else:
                        scope_id = "global"
                        old_name = scope_var_id

                    if scope_id not in result.mappings:
                        result.mappings[scope_id] = {}
                    result.mappings[scope_id][old_name] = new_name
                    result.reasons[scope_var_id] = reason
                    result.total_named += 1

                logger.info(
                    "Batch %d/%d: %d degisken isimlendirildi",
                    batch_idx + 1, len(batches), len(batch_mappings),
                )

            except Exception as exc:
                result.failed_batches += 1
                error_msg = f"Batch {batch_idx + 1}/{len(batches)} hatasi: {exc}"
                result.errors.append(error_msg)
                logger.warning(error_msg)

        result.success = result.total_named > 0 or result.failed_batches == 0
        result.duration_seconds = time.monotonic() - t0

        logger.info(
            "LLM naming tamamlandi: %d isimlendirildi, %d batch, %d hata (%.1fs)",
            result.total_named, result.total_batches,
            result.failed_batches, result.duration_seconds,
        )

        return result

    def name_variables_from_list(
        self,
        variables: list[dict[str, Any]],
    ) -> LLMNamingResult:
        """Dogrudan degisken listesi ile isimlendirme yap.

        Context JSON okumadan, hazir degisken bilgisiyle calismak icin.
        Test ve hizli denemeler icin uygun.

        Args:
            variables: Her biri {old_name, scope_id, apis, props, data_flow,
                       confidence, code_snippet, ...} iceren dict listesi.

        Returns:
            LLMNamingResult.
        """
        t0 = time.monotonic()
        result = LLMNamingResult(model_used=self.model)

        if not self._cli_available:
            result.errors.append("Claude CLI bulunamadi")
            result.duration_seconds = time.monotonic() - t0
            return result

        if not variables:
            result.success = True
            result.duration_seconds = time.monotonic() - t0
            return result

        batches = [
            variables[i : i + self.batch_size]
            for i in range(0, len(variables), self.batch_size)
        ]
        result.total_batches = len(batches)

        for batch_idx, batch in enumerate(batches):
            try:
                prompt = self._prepare_batch_from_dicts(batch)
                response = self._call_claude(prompt)
                batch_mappings = self._parse_response(response)

                for item in batch_mappings:
                    scope_var_id = item.get("id", "")
                    new_name = item.get("new_name", "")
                    reason = item.get("reason", "")

                    if not scope_var_id or not new_name:
                        continue

                    parts = scope_var_id.split("::", 1)
                    if len(parts) == 2:
                        scope_id, old_name = parts
                    else:
                        scope_id = "global"
                        old_name = scope_var_id

                    if scope_id not in result.mappings:
                        result.mappings[scope_id] = {}
                    result.mappings[scope_id][old_name] = new_name
                    result.reasons[scope_var_id] = reason
                    result.total_named += 1

            except Exception as exc:
                result.failed_batches += 1
                result.errors.append(f"Batch {batch_idx + 1} hatasi: {exc}")

        result.success = result.total_named > 0 or result.failed_batches == 0
        result.duration_seconds = time.monotonic() - t0
        return result

    # ---------------------------------------------------------------
    # Internal methods
    # ---------------------------------------------------------------

    def _extract_low_confidence_vars(
        self, context_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Context JSON'dan dusuk-confidence degiskenleri cikar.

        Filtre kriterleri:
        - confidence < self.min_confidence
        - reference_count >= self.min_references
        - Tek harfli veya anlamsiz isim (2 harften kisa veya pattern: e, t, n, r, ...)
        """
        variables_raw = context_data.get("variables", [])
        if not variables_raw:
            # Alternatif format: scopes icinde olabilir
            scopes = context_data.get("scopes", {})
            for scope_id, scope_data in scopes.items():
                scope_vars = scope_data.get("variables", [])
                for v in scope_vars:
                    v.setdefault("scope_id", scope_id)
                variables_raw.extend(scope_vars)

        candidates = []
        for v in variables_raw:
            confidence = v.get("confidence", 1.0)
            ref_count = v.get("reference_count", v.get("references", 0))
            name = v.get("name", v.get("old_name", ""))

            # Filtre: dusuk confidence + yeterli referans + kisa isim
            if confidence < self.min_confidence and ref_count >= self.min_references:
                candidates.append(v)
            elif len(name) <= 2 and ref_count >= self.min_references:
                # Tek/cift harfli degiskenler her zaman aday
                candidates.append(v)

        # Reference count'a gore sirala (cok kullanilan = daha onemli)
        candidates.sort(
            key=lambda v: v.get("reference_count", v.get("references", 0)),
            reverse=True,
        )

        return candidates

    def _prepare_batch(
        self,
        variables: list[dict[str, Any]],
        source_lines: list[str],
    ) -> str:
        """Tek batch icin prompt olustur -- context JSON formatindan."""
        contexts = []
        for v in variables:
            old_name = v.get("name", v.get("old_name", "unknown"))
            scope_id = v.get("scope_id", v.get("scope", "global"))
            decl_type = v.get("declaration_type", v.get("kind", "var"))
            ref_count = v.get("reference_count", v.get("references", 0))
            api_calls = v.get("api_calls", v.get("apis", []))
            properties = v.get("properties", v.get("props", []))
            data_flow = v.get("data_flow", v.get("assignments", ""))
            current_name = v.get("suggested_name", v.get("current_name", old_name))
            confidence = v.get("confidence", 0.0)

            # Kod snippet'i: degiskenin tanimlandigi satir civarini goster
            code_snippet = self._get_code_snippet(v, source_lines)

            # API ve property listelerini string'e cevir
            if isinstance(api_calls, list):
                api_calls = ", ".join(str(a) for a in api_calls[:10])
            if isinstance(properties, list):
                properties = ", ".join(str(p) for p in properties[:10])
            if isinstance(data_flow, (list, dict)):
                data_flow = json.dumps(data_flow)[:200]

            ctx = VARIABLE_CONTEXT_TEMPLATE.format(
                old_name=old_name,
                scope_id=scope_id,
                declaration_type=decl_type,
                reference_count=ref_count,
                api_calls=api_calls or "none",
                properties=properties or "none",
                data_flow=data_flow or "none",
                current_name=current_name,
                confidence=f"{confidence:.2f}",
                code_snippet=code_snippet,
            )
            contexts.append(ctx)

        variables_context = "\n".join(contexts)
        return NAMING_PROMPT.format(variables_context=variables_context)

    def _prepare_batch_from_dicts(
        self,
        variables: list[dict[str, Any]],
    ) -> str:
        """Dogrudan dict listesinden prompt olustur."""
        contexts = []
        for v in variables:
            old_name = v.get("old", v.get("old_name", v.get("name", "unknown")))
            scope_id = v.get("scope", v.get("scope_id", "global"))
            api_calls = v.get("apis", v.get("api_calls", []))
            properties = v.get("props", v.get("properties", []))
            data_flow = v.get("data_flow", "")
            code_snippet = v.get("code_snippet", v.get("code", "// no code available"))
            current_name = v.get("current_name", old_name)
            confidence = v.get("confidence", 0.0)
            ref_count = v.get("reference_count", v.get("references", 0))
            decl_type = v.get("declaration_type", v.get("kind", "var"))

            if isinstance(api_calls, list):
                api_calls = ", ".join(str(a) for a in api_calls[:10])
            if isinstance(properties, list):
                properties = ", ".join(str(p) for p in properties[:10])

            ctx = VARIABLE_CONTEXT_TEMPLATE.format(
                old_name=old_name,
                scope_id=scope_id,
                declaration_type=decl_type,
                reference_count=ref_count,
                api_calls=api_calls or "none",
                properties=properties or "none",
                data_flow=data_flow or "none",
                current_name=current_name,
                confidence=f"{confidence:.2f}",
                code_snippet=code_snippet,
            )
            contexts.append(ctx)

        variables_context = "\n".join(contexts)
        return NAMING_PROMPT.format(variables_context=variables_context)

    def _get_code_snippet(
        self,
        variable: dict[str, Any],
        source_lines: list[str],
    ) -> str:
        """Degiskenin tanimlandigi bolgenin kod snippet'ini cikar."""
        # Satir numarasi varsa onu kullan
        line_num = variable.get("line", variable.get("start_line", 0))
        if line_num > 0 and line_num <= len(source_lines):
            start = max(0, line_num - 3)
            end = min(len(source_lines), line_num + self.max_code_lines - 3)
            return "\n".join(source_lines[start:end])

        # Satir numarasi yoksa, degisken adini kaynak kodda ara
        name = variable.get("name", variable.get("old_name", ""))
        if name and len(name) >= 1:
            for i, line in enumerate(source_lines):
                if name in line:
                    start = max(0, i - 2)
                    end = min(len(source_lines), i + self.max_code_lines - 2)
                    return "\n".join(source_lines[start:end])

        return "// code snippet not available"

    def _call_claude(self, prompt: str, retry: bool = True) -> str:
        """Claude CLI subprocess cagrisi.

        Args:
            prompt: Gonderilecek prompt.
            retry: JSON parse hatasi durumunda tekrar dene.

        Returns:
            Claude'un yaniti (string).

        Raises:
            RuntimeError: CLI basarisiz olursa.
            subprocess.TimeoutExpired: Timeout asimi.
        """
        cmd = [
            str(CLAUDE_CLI_PATH),
            "-p",
            prompt,
            "--model",
            self.model,
        ]

        logger.debug("Claude CLI cagriliyor: model=%s, prompt_len=%d", self.model, len(prompt))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Claude CLI timeout ({self.timeout}s)"
            )

        if proc.returncode != 0:
            error_detail = proc.stderr[:500] if proc.stderr else "no stderr"
            raise RuntimeError(
                f"Claude CLI hata kodu {proc.returncode}: {error_detail}"
            )

        response = proc.stdout.strip()
        if not response:
            raise RuntimeError("Claude CLI bos yanit dondurdu")

        return response

    def _parse_response(self, response: str) -> list[dict[str, Any]]:
        """Claude yanitindan JSON mapping cikar.

        Beklenen format:
        {"renames": [{"id": "scope::var", "new_name": "...", "reason": "..."}]}

        Args:
            response: Claude CLI ciktisi.

        Returns:
            Rename item listesi.
        """
        # JSON blogu bul -- ```json ... ``` veya { ... } veya [ ... ]
        # Once markdown code fence icinde JSON ara
        fence_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
        if fence_match:
            json_str = fence_match.group(1)
        else:
            # Dogrudan JSON objesi ara
            json_match = re.search(r'\{[\s\S]*"renames"[\s\S]*\}', response)
            if json_match:
                json_str = json_match.group()
            else:
                # Son care: tum yaniti JSON olarak parse etmeyi dene
                json_str = response

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            # Retry: daha agresif JSON cikarma
            # { ile baslayip } ile biten en buyuk blogu bul
            brace_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response)
            if brace_match:
                try:
                    data = json.loads(brace_match.group())
                except json.JSONDecodeError:
                    logger.warning("JSON parse basarisiz, yanit: %s", response[:300])
                    return []
            else:
                logger.warning("Yanitte JSON bulunamadi: %s", response[:300])
                return []

        # "renames" anahtarini cikar
        if isinstance(data, dict):
            renames = data.get("renames", [])
        elif isinstance(data, list):
            renames = data
        else:
            logger.warning("Beklenmeyen JSON yapisi: %s", type(data))
            return []

        # Validate
        valid = []
        for item in renames:
            if not isinstance(item, dict):
                continue
            if "id" in item and "new_name" in item:
                valid.append(item)
            elif "old_name" in item and "new_name" in item:
                # Alternatif format
                item["id"] = item.get("scope", "global") + "::" + item["old_name"]
                valid.append(item)

        return valid
