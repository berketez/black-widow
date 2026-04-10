"""Semantic variable renaming -- tek harfli degiskenleri anlamli isimlere donustur.

Babel AST uzerinden degisken kullanim baglamini analiz ederek:
- require('fs') -> fileSystem
- Express callback (e, t, n) -> (request, response, next)
- Event handler x.on('click', z) -> z = onClickHandler
- Promise x.then(y) -> y = onResolve

SubprocessRunner ile scripts/rename-variables.mjs calistirilir.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from karadul.config import Config
from karadul.core.subprocess_runner import SubprocessRunner

logger = logging.getLogger(__name__)


@dataclass
class RenameResult:
    """Variable renaming sonucu.

    Attributes:
        success: Renaming basarili mi.
        variables_renamed: Yeniden adlandirilan degisken sayisi.
        mappings: Eski isim -> yeni isim eslesmesi.
        output_file: Cikti dosyasi yolu.
        errors: Hata mesajlari.
    """

    success: bool
    variables_renamed: int
    mappings: dict[str, str]
    output_file: Path | None
    errors: list[str] = field(default_factory=list)


class VariableRenamer:
    """Semantic variable renaming -- tek harfli degiskenleri anlamli isimlere donustur.

    Strateji:
    1. Babel AST parse et
    2. Her degisken icin kullanim baglamini analiz et:
       - Fonksiyon parametresi: request/response/callback/options/config
       - Return type: isX -> boolean, onX -> event handler
       - Scope: global vs local
       - Atama: require('fs') -> fileSystem
    3. scripts/rename-variables.mjs subprocess ile calistir

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.runner = SubprocessRunner(config)
        self._script_path = config.scripts_dir / "rename-variables.mjs"

    def rename(
        self,
        input_file: Path,
        output_file: Path,
        context: dict | None = None,
    ) -> RenameResult:
        """Degiskenleri anlamli isimlerle yeniden adlandir.

        Args:
            input_file: Girdi JS dosyasi.
            output_file: Cikti JS dosyasi.
            context: Ek baglamsal bilgi (statik analiz sonuclari vb.).

        Returns:
            RenameResult: Sonuc.
        """
        if not input_file.exists():
            return RenameResult(
                success=False,
                variables_renamed=0,
                mappings={},
                output_file=None,
                errors=[f"Girdi dosyasi bulunamadi: {input_file}"],
            )

        args = [str(input_file), str(output_file)]

        # Context varsa gecici dosyaya yaz ve --context arg ekle
        context_file: Path | None = None
        if context:
            context_file = output_file.parent / ".rename_context.json"
            try:
                context_file.write_text(
                    json.dumps(context, ensure_ascii=False),
                    encoding="utf-8",
                )
                args.extend(["--context", str(context_file)])
            except OSError as exc:
                logger.warning("Context dosyasi yazilamadi: %s", exc)

        try:
            result_json = self.runner.run_node_script(
                script_path=self._script_path,
                args=args,
                timeout=self.config.timeouts.babel_parse,
                cwd=self.config.scripts_dir,
            )
        except FileNotFoundError as exc:
            return RenameResult(
                success=False,
                variables_renamed=0,
                mappings={},
                output_file=None,
                errors=[f"rename-variables.mjs bulunamadi: {exc}"],
            )
        except RuntimeError as exc:
            return RenameResult(
                success=False,
                variables_renamed=0,
                mappings={},
                output_file=None,
                errors=[f"rename-variables.mjs hatasi: {exc}"],
            )
        finally:
            # Context gecici dosyasini temizle
            if context_file and context_file.exists():
                try:
                    context_file.unlink()
                except OSError:
                    pass

        mappings = result_json.get("mappings", {})
        renamed_count = result_json.get("renamed", 0)
        script_errors = result_json.get("errors", [])
        success = result_json.get("success", False)

        if success:
            logger.info(
                "Variable renaming: %d degisken yeniden adlandirildi",
                renamed_count,
            )
            for old, new in list(mappings.items())[:10]:
                logger.debug("  %s -> %s", old, new)
        else:
            logger.warning("Variable renaming basarisiz")

        return RenameResult(
            success=success,
            variables_renamed=renamed_count,
            mappings=mappings,
            output_file=output_file if success and output_file.exists() else None,
            errors=script_errors,
        )
