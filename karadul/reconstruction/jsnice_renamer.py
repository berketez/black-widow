"""JSNice entegrasyonu — istatistiksel model ile JS değişken isim kurtarma.

JSNice (ETH Zürich) CRF tabanlı bir modeldir; LLM değildir.

UYARI (P20, 2026-11-18, kaynak okunarak doğrulandı): bu sınıfın çağırdığı
``jsnice`` komutu (npm ``jsnice`` 0.2.0, /opt/homebrew/lib/node_modules/jsnice)
YEREL ÇALIŞMAZ: ``lib/index.js`` girdinin tamamını ``http://www.jsnice.org/beautify``
adresine düz HTTP (port 80) ile POST eder. Eski açıklamadaki "lokal çalışır"
ve "%48.3 doğruluk" ifadeleri doğrulanmamıştı; ilki yanlıştır. Analiz edilen
kodu üçüncü tarafa şifresiz göndermek ağ kapısını delmek demektir; bu yüzden
sınıf açık ağ izni (``allow_network=True``) verilmeden hiçbir süreç başlatmaz.
Ürün akışına bağlı değildir (bkz. docs/arge/2026-11-18_onarim/P20.md, kalem 5).

Kullanim:
    renamer = JSNiceRenamer(allow_network=True)  # yalnız bilinçli ağ izniyle
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


_NETWORK_REFUSAL = (
    "jsnice komutu girdiyi www.jsnice.org'a düz HTTP ile gönderir (yerel değil); "
    "ağ izni yok (JSNiceRenamer(allow_network=True) gerekir)"
)


@dataclass
class JSNiceResult:
    success: bool
    output_file: Path | None = None
    # None = ölçülmedi. Eskiden çıktıda geçen her 4+ harfli küçük sözcük
    # ("function", "return" dahil) "yeniden adlandırılan değişken" sayılıyordu.
    variables_renamed: int | None = None
    types_inferred: int = 0
    errors: list[str] = field(default_factory=list)


class JSNiceRenamer:
    """JSNice istatistiksel model ile JS değişken isimlendirme.

    CRF (Conditional Random Fields) tabanlı — binlerce açık kaynak
    JS projesinden öğrenilmiş isim tahmin modeli.
    %48.3 doğruluk, 2.9ms/tahmin.
    """

    def __init__(self, *, allow_network: bool = False) -> None:
        self._jsnice_path = shutil.which("jsnice")
        self._allow_network = allow_network is True

    @property
    def is_available(self) -> bool:
        return self._jsnice_path is not None and self._allow_network

    def rename(self, input_file: Path, output_file: Path) -> JSNiceResult:
        """JSNice ile değişken isimlerini tahmin et.

        Args:
            input_file: Minified JS dosyası.
            output_file: İsimlendirilmiş çıktı dosyası.

        Returns:
            JSNiceResult
        """
        if not self._allow_network:
            return JSNiceResult(success=False, errors=[_NETWORK_REFUSAL])
        if self._jsnice_path is None:
            return JSNiceResult(
                success=False,
                errors=["jsnice kurulu değil"],
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

            # Yeniden adlandırılan değişken sayısı ÖLÇÜLMÜYOR (None): eski
            # sözcük farkı sezgisi anahtar sözcükleri de sayıyordu.
            return JSNiceResult(
                success=True,
                output_file=output_path,
                variables_renamed=None,
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
        """JS kod parçasını JSNice'den geçir, sonucu döndür (ağ izni şart)."""
        if self._jsnice_path is None or not self._allow_network:
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
