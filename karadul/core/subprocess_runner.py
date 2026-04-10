"""Node.js ve harici arac subprocess yonetimi.

JSON-over-stdout protokolu: Node.js scriptleri stdout'a JSON yazarlar,
bu class parse eder. stderr her zaman loglarda saklanir.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config

logger = logging.getLogger(__name__)


@dataclass
class SubprocessResult:
    """Subprocess calisma sonucu.

    Attributes:
        success: Basarili tamamlanip tamamlanmadigi (returncode == 0).
        returncode: Process donus kodu.
        stdout: Standart cikti (raw string).
        stderr: Hata ciktisi (raw string).
        parsed_json: stdout JSON olarak parse edilebildiyse sonuc.
        duration_seconds: Calisma suresi (saniye).
    """

    success: bool
    returncode: int
    stdout: str = ""
    stderr: str = ""
    parsed_json: dict[str, Any] | None = None
    duration_seconds: float = 0.0


class SubprocessRunner:
    """Harici arac ve Node.js script calistiricisi.

    JSON-over-stdout protokolu:
    - Node.js scriptleri sonucu ``console.log(JSON.stringify(result))`` ile yazarlar.
    - Bu class stdout'un son satirini JSON olarak parse eder.
    - Ara satirlar (log/debug ciktilari) atlanir.

    Args:
        config: Merkezi konfigurasyon (tool path'leri ve timeout'lar icin).
    """

    def __init__(self, config: Config) -> None:
        self._config = config

    def run_command(
        self,
        cmd: list[str],
        timeout: int | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> SubprocessResult:
        """Harici komut calistir.

        Args:
            cmd: Komut ve argumanlari (orn: ["node", "script.js", "--arg"]).
            timeout: Zaman asimi (saniye). None ise Config'deki varsayilan.
            cwd: Calisma dizini. None ise mevcut dizin.
            env: Ek ortam degiskenleri. Mevcut env'ye merge edilir.

        Returns:
            SubprocessResult: Calisma sonucu.
        """
        effective_timeout = timeout or self._config.timeouts.subprocess

        import os
        import time

        # Ortam degiskenlerini hazirla
        run_env: dict[str, str] | None = None
        if env:
            run_env = {**os.environ, **env}

        cmd_str = " ".join(str(c) for c in cmd)
        logger.info("Subprocess baslatiliyor: %s", cmd_str)

        start = time.monotonic()

        try:
            proc = subprocess.run(
                [str(c) for c in cmd],
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                cwd=str(cwd) if cwd else None,
                env=run_env,
            )

            duration = time.monotonic() - start

            # stderr'i logla (bos degilse)
            if proc.stderr.strip():
                for line in proc.stderr.strip().splitlines()[:20]:
                    logger.debug("  [stderr] %s", line)

            # JSON parse denemesi
            parsed = self._try_parse_json(proc.stdout)

            result = SubprocessResult(
                success=proc.returncode == 0,
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                parsed_json=parsed,
                duration_seconds=duration,
            )

            if not result.success:
                logger.warning(
                    "Subprocess basarisiz (code=%d): %s",
                    proc.returncode, cmd_str,
                )

            return result

        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start
            logger.error(
                "Subprocess zaman asimi (%ds): %s", effective_timeout, cmd_str,
            )
            return SubprocessResult(
                success=False,
                returncode=-1,
                stderr=f"Timeout after {effective_timeout}s",
                duration_seconds=duration,
            )

        except FileNotFoundError as exc:
            duration = time.monotonic() - start
            logger.error("Komut bulunamadi: %s (%s)", cmd[0], exc)
            return SubprocessResult(
                success=False,
                returncode=-1,
                stderr=f"Command not found: {cmd[0]}",
                duration_seconds=duration,
            )

        except OSError as exc:
            duration = time.monotonic() - start
            logger.error("Subprocess OS hatasi: %s", exc)
            return SubprocessResult(
                success=False,
                returncode=-1,
                stderr=str(exc),
                duration_seconds=duration,
            )

    def run_node_script(
        self,
        script_path: Path,
        args: list[str] | None = None,
        timeout: int | None = None,
        cwd: Path | None = None,
    ) -> dict[str, Any]:
        """Node.js scripti calistir ve JSON sonucunu dondur.

        JSON-over-stdout protokolunu kullanir: script'in stdout'a yazdigi
        son JSON satirini parse eder.

        Args:
            script_path: .js dosyasinin yolu.
            args: Script argumanlari.
            timeout: Zaman asimi (saniye).
            cwd: Calisma dizini.

        Returns:
            Parse edilmis JSON sonucu.

        Raises:
            FileNotFoundError: Script dosyasi bulunamazsa.
            RuntimeError: Script basarisiz olursa veya JSON parse edilemezse.
        """
        script = Path(script_path).resolve()
        if not script.exists():
            raise FileNotFoundError(f"Node.js script bulunamadi: {script}")

        node_path = str(self._config.tools.node)
        cmd = [node_path, str(script)] + (args or [])

        result = self.run_command(cmd, timeout=timeout, cwd=cwd)

        if not result.success:
            raise RuntimeError(
                f"Node.js script basarisiz (code={result.returncode}): "
                f"{script.name}\nstderr: {result.stderr[:500]}"
            )

        if result.parsed_json is None:
            raise RuntimeError(
                f"Node.js script JSON ciktisi uretemedi: {script.name}\n"
                f"stdout: {result.stdout[:500]}"
            )

        return result.parsed_json

    def run_synchrony(
        self,
        input_file: Path,
        output_file: Path,
    ) -> bool:
        """synchrony deobfuscation araci calistir.

        synchrony, obfuscated JavaScript dosyasini cozumler.

        Args:
            input_file: Obfuscated JS dosyasinin yolu.
            output_file: Cozumlenmis ciktinin yazilacagi yol.

        Returns:
            Basarili ise True, aksi halde False.
        """
        synchrony_path = str(self._config.tools.synchrony)
        timeout = self._config.timeouts.synchrony

        cmd = [synchrony_path, str(input_file)]

        result = self.run_command(cmd, timeout=timeout)

        if not result.success:
            logger.error("synchrony basarisiz: %s", result.stderr[:300])
            return False

        # synchrony stdout'a deobfuscated kodu yazar
        output = result.stdout
        if not output.strip():
            logger.error("synchrony bos cikti uretti: %s", input_file)
            return False

        try:
            Path(output_file).write_text(output, encoding="utf-8")
            logger.info("synchrony basarili: %s -> %s", input_file, output_file)
            return True
        except OSError as exc:
            logger.error("synchrony ciktisi yazilamadi: %s", exc)
            return False

    def run_strings(
        self,
        binary_path: Path,
        min_length: int | None = None,
    ) -> list[str]:
        """macOS ``strings`` komutu ile binary'den string cikar.

        Args:
            binary_path: Binary dosya yolu.
            min_length: Minimum string uzunlugu. None ise Config'deki deger.

        Returns:
            Cikarilan string listesi.
        """
        min_len = min_length or self._config.analysis.string_min_length
        strings_path = str(self._config.tools.strings)
        cmd = [strings_path, "-n", str(min_len), str(binary_path)]

        result = self.run_command(cmd, timeout=60)

        if not result.success:
            logger.warning("strings komutu basarisiz: %s", binary_path)
            return []

        return result.stdout.splitlines()

    def run_otool(
        self,
        binary_path: Path,
        flags: list[str] | None = None,
    ) -> str:
        """macOS ``otool`` komutu calistir.

        Args:
            binary_path: Binary dosya yolu.
            flags: otool flag'leri (orn: ["-L"] loaded libraries, ["-l"] load commands).

        Returns:
            otool ciktisi (string).
        """
        otool_path = str(self._config.tools.otool)
        cmd = [otool_path] + (flags or ["-L"]) + [str(binary_path)]

        result = self.run_command(cmd, timeout=30)

        if not result.success:
            logger.warning("otool basarisiz: %s", result.stderr[:200])
            return ""

        return result.stdout

    @staticmethod
    def _try_parse_json(stdout: str) -> dict[str, Any] | None:
        """stdout'tan JSON parse etmeyi dene.

        Strateji: Son satirdan baslayarak yukari dogru ilk gecerli JSON'u bul.
        Bu sayede script'in ara satirlardaki log ciktilari atlanir.
        """
        lines = stdout.strip().splitlines()

        # Sondan basa dogru dene
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            if line.startswith("{") or line.startswith("["):
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        return parsed
                    # Array ise dict'e sar
                    if isinstance(parsed, list):
                        return {"items": parsed}
                except json.JSONDecodeError:
                    continue

        # Tek satirda JSON yoksa tum ciktiyi dene (multiline JSON)
        full = stdout.strip()
        if full.startswith("{"):
            try:
                parsed = json.loads(full)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        return None
