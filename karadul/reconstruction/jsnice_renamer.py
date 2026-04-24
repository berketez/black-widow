"""JSNice entegrasyonu — istatistiksel model ile JS değişken isim kurtarma.

JSNice (ETH Zürich) CRF tabanlı küçük model kullanarak minified JavaScript'teki
değişken isimlerini %48.3 doğrulukla tahmin eder. LLM DEĞİL — lokal çalışır.

Kullanim:
    renamer = JSNiceRenamer()
    if renamer.is_available:
        result = renamer.rename(input_file, output_file)
"""

from __future__ import annotations

import logging
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class JSNiceResult:
    success: bool
    output_file: Path | None = None
    variables_renamed: int = 0
    types_inferred: int = 0
    errors: list[str] = field(default_factory=list)


class JSNiceRenamer:
    """JSNice istatistiksel model ile JS değişken isimlendirme.

    CRF (Conditional Random Fields) tabanlı — binlerce açık kaynak
    JS projesinden öğrenilmiş isim tahmin modeli.
    %48.3 doğruluk, 2.9ms/tahmin.
    """

    def __init__(self) -> None:
        self._jsnice_path = shutil.which("jsnice")

    @property
    def is_available(self) -> bool:
        return self._jsnice_path is not None

    def rename(self, input_file: Path, output_file: Path) -> JSNiceResult:
        """JSNice ile değişken isimlerini tahmin et.

        Args:
            input_file: Minified JS dosyası.
            output_file: İsimlendirilmiş çıktı dosyası.

        Returns:
            JSNiceResult
        """
        if self._jsnice_path is None:
            return JSNiceResult(
                success=False,
                errors=["jsnice kurulu değil: npm install -g jsnice"],
            )

        input_path = Path(input_file)
        if not input_path.exists():
            return JSNiceResult(success=False, errors=[f"Dosya bulunamadı: {input_path}"])

        try:
            result = subprocess.run(
                [self._jsnice_path, str(input_path)],
                capture_output=True, text=True, timeout=300,
            )

            if result.returncode != 0:
                return JSNiceResult(
                    success=False,
                    errors=[f"jsnice hatası: {result.stderr[:500]}"],
                )

            output = result.stdout
            if not output.strip():
                return JSNiceResult(
                    success=False,
                    errors=["jsnice boş çıktı verdi"],
                )

            # Çıktıyı yaz
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(output, encoding="utf-8")

            # İstatistikler
            # JSNice /** @type ... */ ve @param ekler
            types_count = output.count("@type")
            params_count = output.count("@param")

            # Kaç değişken rename edildiğini tahmin et
            # (orijinal vs çıktıdaki farklı identifier'lar)
            original = input_path.read_text(encoding="utf-8", errors="replace")
            import re
            orig_vars = set(re.findall(r'\b([a-z]\w{0,2})\b', original))
            new_vars = set(re.findall(r'\b([a-z]\w{3,})\b', output))
            renamed = len(new_vars - orig_vars)

            return JSNiceResult(
                success=True,
                output_file=output_path,
                variables_renamed=renamed,
                types_inferred=types_count + params_count,
            )

        except subprocess.TimeoutExpired:
            return JSNiceResult(
                success=False,
                errors=["jsnice timeout (300s)"],
            )
        except Exception as exc:
            return JSNiceResult(
                success=False,
                errors=[f"jsnice hatası: {exc}"],
            )

    def rename_chunk(self, js_code: str) -> str | None:
        """JS kod parçasını JSNice'den geçir, sonucu döndür."""
        if self._jsnice_path is None:
            return None

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write(js_code)
            tmp_input = Path(f.name)

        try:
            result = subprocess.run(
                [self._jsnice_path, str(tmp_input)],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except Exception:
            logger.debug("Dosya yazma basarisiz, atlaniyor", exc_info=True)
        finally:
            tmp_input.unlink(missing_ok=True)

        return None
