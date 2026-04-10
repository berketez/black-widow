"""Babel AST transform pipeline.

scripts/deobfuscate.mjs uzerinden Babel AST donusumlerini calistirir.
Desteklenen transform'lar:
- constant_folding: Sabit ifadeleri hesapla (1+2 -> 3)
- dead_code_elimination: Ulasilamaz kodu sil
- string_unhex: Hex string literal'leri coz ("\\x48\\x65\\x6c\\x6c\\x6f" -> "Hello")
- computed_to_static: Computed property'leri static'e donustur (obj["foo"] -> obj.foo)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..config import Config
from ..core.subprocess_runner import SubprocessRunner

logger = logging.getLogger(__name__)

# Desteklenen Babel transform'lari
AVAILABLE_TRANSFORMS = (
    "constant_folding",
    "dead_code_elimination",
    "string_unhex",
    "computed_to_static",
)


class BabelPipeline:
    """Babel AST transform wrapper.

    scripts/deobfuscate.mjs'i SubprocessRunner uzerinden cagirarak
    JavaScript dosyalarina AST donusumleri uygular.

    JSON-over-stdout protokolu: script stdout'a JSON sonucu yazar,
    SubprocessRunner parse eder.

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._runner = SubprocessRunner(config)
        self._script_path = config.scripts_dir / "deobfuscate.mjs"

    def is_available(self) -> bool:
        """Babel pipeline scripti mevcut mu?"""
        return self._script_path.exists()

    def transform(
        self,
        input_file: Path,
        output_file: Path,
        transforms: list[str] | None = None,
    ) -> dict[str, Any]:
        """Babel AST transform'larini uygula.

        Args:
            input_file: Girdi JS dosyasi.
            output_file: Donusturulmus ciktinin yazilacagi yol.
            transforms: Uygulanacak transform listesi.
                None ise tum desteklenen transform'lar uygulanir.

        Returns:
            Sonuc dict'i. Anahtarlar:
            - success (bool): Basarili mi
            - transforms_applied (list[str]): Uygulanan transform'lar
            - stats (dict): Istatistikler (fonksiyon_sayisi, string_sayisi vb.)
            - errors (list[str]): Hata mesajlari

        Raises:
            FileNotFoundError: Script veya girdi dosyasi yoksa.
            RuntimeError: Script calisma hatasi.
        """
        if not self._script_path.exists():
            raise FileNotFoundError(
                f"Babel pipeline scripti bulunamadi: {self._script_path}"
            )
        if not input_file.exists():
            raise FileNotFoundError(f"Girdi dosyasi bulunamadi: {input_file}")

        # Transform listesini dogrula
        effective_transforms = transforms or list(AVAILABLE_TRANSFORMS)
        for t in effective_transforms:
            if t not in AVAILABLE_TRANSFORMS:
                logger.warning("Bilinmeyen transform atlanacak: %s", t)

        valid_transforms = [
            t for t in effective_transforms if t in AVAILABLE_TRANSFORMS
        ]

        # Output dizinini olustur
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Script argumanlari
        args = [
            str(input_file),
            "--output", str(output_file),
            "--transforms", ",".join(valid_transforms),
        ]

        logger.info(
            "Babel pipeline baslatiliyor: %s (transforms: %s)",
            input_file.name,
            ", ".join(valid_transforms),
        )

        try:
            result = self._runner.run_node_script(
                self._script_path,
                args=args,
                timeout=self._config.timeouts.babel_parse,
            )
            logger.info(
                "Babel pipeline basarili: %s -> %s",
                input_file.name,
                output_file.name,
            )
            return result

        except RuntimeError as exc:
            logger.error("Babel pipeline hatasi: %s", exc)
            return {
                "success": False,
                "transforms_applied": [],
                "stats": {},
                "errors": [str(exc)],
            }

    def analyze(self, input_file: Path) -> dict[str, Any]:
        """Babel AST analizi yap (transform uygulamadan).

        Fonksiyon, string, import/export ve webpack module bilgilerini cikarir.

        Args:
            input_file: Analiz edilecek JS dosyasi.

        Returns:
            AST analiz sonucu (JSON dict).
        """
        if not self._script_path.exists():
            raise FileNotFoundError(
                f"Babel pipeline scripti bulunamadi: {self._script_path}"
            )

        args = [
            str(input_file),
            "--analyze-only",
        ]

        logger.info("Babel AST analizi: %s", input_file.name)

        try:
            return self._runner.run_node_script(
                self._script_path,
                args=args,
                timeout=self._config.timeouts.babel_parse,
            )
        except RuntimeError as exc:
            logger.error("Babel AST analiz hatasi: %s", exc)
            return {
                "success": False,
                "stats": {},
                "errors": [str(exc)],
            }
