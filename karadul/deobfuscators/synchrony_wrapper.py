"""synchrony CLI wrapper.

synchrony (https://github.com/nicholasgrose/synchrony) JavaScript deobfuscation
aracinin Python wrapper'i. Obfuscated JS dosyalarini cozumler.

synchrony'nin -o flag'i ile dogrudan dosyaya yazma desteklenir.
Bu sayede buyuk dosyalarda stdout memory sorunu onlenir.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path

from ..config import Config
from ..core.subprocess_runner import SubprocessRunner

logger = logging.getLogger(__name__)


class SynchronyWrapper:
    """synchrony CLI wrapper.

    synchrony'yi dogrudan SubprocessRunner.run_command() ile cagiriyoruz
    (run_synchrony() yerine) cunku:
    1. -o flag'i ile output dosyasina dogrudan yazabiliyoruz
    2. Buyuk dosyalarda stdout bellekte tutulmaz
    3. Hata durumunda stderr'den detayli bilgi alinir

    Args:
        config: Merkezi konfigurasyon (tool path + timeout icin).
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._runner = SubprocessRunner(config)

    def is_available(self) -> bool:
        """synchrony kurulu ve calisabilir mi kontrol et.

        Hem dosya varligi hem de --version ciktisi kontrol edilir.
        """
        sync_path = self._config.tools.synchrony

        # Dosya var mi?
        if not Path(sync_path).exists() and not shutil.which(str(sync_path)):
            logger.debug("synchrony bulunamadi: %s", sync_path)
            return False

        # Calisabiliyor mu?
        result = self._runner.run_command(
            [str(sync_path), "--version"],
            timeout=10,
        )
        if result.success:
            version = result.stdout.strip()
            logger.debug("synchrony mevcut: %s", version)
            return True

        logger.debug("synchrony calistirilmiyor: %s", result.stderr[:200])
        return False

    def deobfuscate(self, input_file: Path, output_file: Path) -> bool:
        """synchrony ile JavaScript dosyasini deobfuscate et.

        synchrony -o flag'i ile ciktiyi dogrudan dosyaya yazar.
        Bu sayede stdout memory overhead'i onlenir.

        Args:
            input_file: Obfuscated JS dosyasinin yolu.
            output_file: Deobfuscated ciktinin yazilacagi yol.

        Returns:
            Basarili ise True, aksi halde False.
        """
        sync_path = str(self._config.tools.synchrony)
        timeout = self._config.timeouts.synchrony

        # Output dizinini olustur
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Shebang satirini soy -- synchrony'nin acorn parser'i #! parse edemiyor
        actual_input = input_file
        shebang_line = None
        stripped_tmp = None

        try:
            with open(input_file, "r", encoding="utf-8", errors="replace") as f:
                first_line = f.readline()
            if first_line.startswith("#!"):
                shebang_line = first_line
                stripped_tmp = tempfile.NamedTemporaryFile(
                    suffix=".js", delete=False, mode="w", encoding="utf-8",
                )
                with open(input_file, "r", encoding="utf-8", errors="replace") as f:
                    f.readline()  # Shebang'i atla
                    for chunk_line in f:
                        stripped_tmp.write(chunk_line)
                stripped_tmp.close()
                actual_input = Path(stripped_tmp.name)
                logger.debug(
                    "Shebang sokuldu: %s -> gecici dosya", input_file.name,
                )
        except OSError as exc:
            logger.warning("Shebang kontrolu basarisiz: %s", exc)

        logger.info(
            "synchrony baslatiliyor: %s -> %s",
            input_file.name, output_file.name,
        )

        # Once default modda dene, basarisiz olursa --type module ile tekrar
        source_types = ["both", "module", "script"]
        result = None

        for source_type in source_types:
            cmd = [
                sync_path,
                str(actual_input),
                "-o", str(output_file),
                "--type", source_type,
            ]

            result = self._runner.run_command(cmd, timeout=timeout)

            if result.success:
                break

            # "ImportDeclaration" hatasi ESM kaynakli, --type module ile tekrar dene
            if "ImportDeclaration" in result.stderr and source_type != "module":
                logger.debug(
                    "synchrony ESM hatasi, --type module ile tekrar deneniyor",
                )
                continue
            # Diger hatalar icin diger source type'lari da dene
            if source_type != source_types[-1]:
                logger.debug(
                    "synchrony --type %s basarisiz, sonraki deneniyor",
                    source_type,
                )
                continue
            break

        # Gecici dosyayi temizle
        if stripped_tmp is not None:
            try:
                Path(stripped_tmp.name).unlink(missing_ok=True)
            except OSError:
                pass

        if result is None or not result.success:
            stderr = result.stderr[:500] if result else "no result"
            returncode = result.returncode if result else -1
            logger.error(
                "synchrony basarisiz (code=%d): %s\nstderr: %s",
                returncode,
                input_file.name,
                stderr,
            )
            return False

        # Cikti dosyasi olusturuldu mu?
        if not output_file.exists():
            # synchrony bazen -o'yu desteklemeyebilir, stdout'a yazmis olabilir
            if result.stdout.strip():
                logger.info(
                    "synchrony -o basarisiz, stdout'tan yaziliyor: %s",
                    output_file.name,
                )
                try:
                    output_file.write_text(result.stdout, encoding="utf-8")
                except OSError as exc:
                    logger.error("Cikti yazma hatasi: %s", exc)
                    return False
            else:
                logger.error("synchrony cikti dosyasi olusturmadi: %s", output_file)
                return False

        # Shebang'i geri ekle (varsa)
        if shebang_line and output_file.exists():
            try:
                content = output_file.read_text(encoding="utf-8")
                output_file.write_text(shebang_line + content, encoding="utf-8")
                logger.debug("Shebang geri eklendi: %s", output_file.name)
            except OSError as exc:
                logger.warning("Shebang geri ekleme hatasi: %s", exc)

        # Cikti boyutunu logla
        out_size = output_file.stat().st_size
        in_size = input_file.stat().st_size
        logger.info(
            "synchrony basarili: %s (%d bytes -> %d bytes, %.1f%%)",
            input_file.name, in_size, out_size,
            (out_size / in_size * 100) if in_size > 0 else 0,
        )
        return True
