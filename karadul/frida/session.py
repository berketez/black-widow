"""Frida session yonetimi -- attach veya spawn.

macOS SIP kisitlamalari nedeniyle bazi process'lere attach
mümkun olmayabilir. Bu durumda anlamli hata mesaji verilir.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

from ..config import Config

logger = logging.getLogger(__name__)

# Frida import kontrolu -- kurulu degilse graceful skip
try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


class FridaNotAvailableError(RuntimeError):
    """frida paketi kurulu degil."""


class FridaAttachError(RuntimeError):
    """Process'e attach olamadi (SIP, izin, process bulunamadi vb.)."""


class FridaSession:
    """Frida session yonetimi -- attach veya spawn.

    Kullanim:
        config = Config()
        session = FridaSession(config)
        pid = session.spawn("/usr/local/bin/node", args=["app.js"])
        session.load_script(Path("hooks/nodejs_hooks.js"))
        session.wait(timeout=10.0)
        messages = session.messages
        session.detach()

    Args:
        config: Merkezi konfigurasyon (timeout'lar icin).
    """

    def __init__(self, config: Config) -> None:
        if not FRIDA_AVAILABLE:
            raise FridaNotAvailableError(
                "frida paketi kurulu degil. "
                "Kurmak icin: pip install frida frida-tools"
            )
        self.config = config
        self._device: Any = None
        self._session: Any = None
        self._scripts: list[Any] = []
        self._messages: list[dict] = []
        self._errors: list[dict] = []
        self._lock = threading.Lock()
        self._pid: int | None = None

    def _get_device(self) -> Any:
        """Local device referansini al (lazy init)."""
        if self._device is None:
            self._device = frida.get_local_device()
        return self._device

    def attach(self, pid_or_name: int | str) -> bool:
        """Calisan process'e attach et.

        Args:
            pid_or_name: Process ID (int) veya process adi (str).

        Returns:
            True ise basarili attach.

        Raises:
            FridaAttachError: Attach basarisiz olursa.
        """
        device = self._get_device()
        timeout = self.config.timeouts.frida_attach

        try:
            logger.info("Frida attach baslatiliyor: %s (timeout=%ds)", pid_or_name, timeout)
            self._session = device.attach(pid_or_name)
            self._session.on("detached", self._on_detached)

            if isinstance(pid_or_name, int):
                self._pid = pid_or_name
            else:
                self._pid = None

            logger.info("Frida attach basarili: %s", pid_or_name)
            return True

        except frida.ProcessNotFoundError:
            msg = f"Process bulunamadi: {pid_or_name}"
            logger.error(msg)
            raise FridaAttachError(msg) from None

        except frida.PermissionDeniedError:
            msg = (
                f"Izin reddedildi: {pid_or_name}. "
                "macOS SIP (System Integrity Protection) bu process'e "
                "attach edilmesini engelliyor olabilir. "
                "csrutil disable veya kullanici process'i deneyin."
            )
            logger.error(msg)
            raise FridaAttachError(msg) from None

        except frida.TransportError as exc:
            msg = f"Frida transport hatasi: {exc}"
            logger.error(msg)
            raise FridaAttachError(msg) from None

        except Exception as exc:
            msg = f"Frida attach hatasi: {type(exc).__name__}: {exc}"
            logger.error(msg)
            raise FridaAttachError(msg) from None

    def spawn(
        self,
        program: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> int:
        """Yeni process spawn et ve attach et.

        Args:
            program: Calistirilacak program yolu.
            args: Program argumanlari.
            env: Ortam degiskenleri.

        Returns:
            Spawn edilen process'in PID'i.

        Raises:
            FridaAttachError: Spawn veya attach basarisiz olursa.
        """
        device = self._get_device()
        spawn_wait = self.config.timeouts.frida_spawn_wait

        try:
            # Spawn argumanlari
            spawn_args = [program] + (args or [])
            spawn_kwargs: dict[str, Any] = {}
            if env:
                spawn_kwargs["env"] = env

            logger.info("Frida spawn baslatiliyor: %s", " ".join(spawn_args))
            pid = device.spawn(spawn_args, **spawn_kwargs)
            self._pid = pid

            # Attach
            self._session = device.attach(pid)
            self._session.on("detached", self._on_detached)

            # Spawn wait -- script'ler yuklensin diye kisa bekleme
            time.sleep(spawn_wait)

            # Resume -- process calismasin baslasin
            device.resume(pid)

            logger.info("Frida spawn basarili: PID=%d, program=%s", pid, program)
            return pid

        except frida.ExecutableNotFoundError:
            msg = f"Program bulunamadi: {program}"
            logger.error(msg)
            raise FridaAttachError(msg) from None

        except Exception as exc:
            msg = f"Frida spawn hatasi: {type(exc).__name__}: {exc}"
            logger.error(msg)
            raise FridaAttachError(msg) from None

    def load_script(self, script_path: Path) -> None:
        """JS hook scriptini dosyadan yükle.

        Args:
            script_path: .js hook dosyasinin yolu.

        Raises:
            FileNotFoundError: Script dosyasi bulunamazsa.
            RuntimeError: Session aktif degilse.
        """
        script_path = Path(script_path).resolve()
        if not script_path.exists():
            raise FileNotFoundError(f"Hook script bulunamadi: {script_path}")

        source = script_path.read_text(encoding="utf-8")
        self.load_script_source(source)
        logger.info("Hook script yuklendi: %s", script_path.name)

    def load_script_source(self, source: str) -> None:
        """JS hook kaynagini dogrudan yükle.

        Args:
            source: JavaScript kaynak kodu.

        Raises:
            RuntimeError: Session aktif degilse.
        """
        if self._session is None:
            raise RuntimeError(
                "Frida session aktif degil. Önce attach() veya spawn() cagirin."
            )

        script = self._session.create_script(source)
        script.on("message", self._on_message)
        script.load()
        self._scripts.append(script)

    def detach(self) -> None:
        """Oturumu kapat ve tüm scriptleri unload et."""
        # Scriptleri unload et
        for script in self._scripts:
            try:
                script.unload()
            except Exception:
                logger.debug("Script zaten unload edilmis olabilir", exc_info=True)
        self._scripts.clear()

        # Session'i detach et
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                logger.debug("Session zaten kapanmis olabilir", exc_info=True)
            self._session = None

        logger.info("Frida session detach edildi.")

    def _on_message(self, message: dict, data: bytes | None) -> None:
        """Frida mesajlarini topla (thread-safe).

        Hook scriptleri send() ile mesaj gonderir.
        message['type'] == 'send' -> payload toplaniyor
        message['type'] == 'error' -> hata kaydediliyor
        """
        with self._lock:
            msg_type = message.get("type", "")

            if msg_type == "send":
                payload = message.get("payload")
                if payload is not None:
                    self._messages.append(payload)
            elif msg_type == "error":
                self._errors.append(message)
                desc = message.get("description", "unknown error")
                logger.warning("Frida script hatasi: %s", desc)
            else:
                logger.debug("Frida bilinmeyen mesaj tipi: %s", msg_type)

    def _on_detached(self, reason: str, crash: Any = None) -> None:
        """Session detach callback'i."""
        logger.info("Frida session detach oldu: reason=%s", reason)
        if crash:
            logger.warning("Process crash: %s", crash)

    @property
    def messages(self) -> list[dict]:
        """Toplanan mesajlar (thread-safe kopyasi)."""
        with self._lock:
            return list(self._messages)

    @property
    def errors(self) -> list[dict]:
        """Toplanan hatalar (thread-safe kopyasi)."""
        with self._lock:
            return list(self._errors)

    @property
    def pid(self) -> int | None:
        """Attach/spawn edilen process'in PID'i."""
        return self._pid

    @property
    def is_attached(self) -> bool:
        """Session aktif mi."""
        return self._session is not None

    def wait(self, timeout: float | None = None) -> None:
        """Belirtilen sure boyunca veri topla.

        Process'in mesaj gondermesi icin bekler. Process erken
        sonlanirsa wait erken doner.

        Args:
            timeout: Bekleme suresi (saniye). None ise config'deki
                     frida_attach timeout'u kullanilir.
        """
        if timeout is None:
            timeout = float(self.config.timeouts.frida_attach)

        logger.info("Frida veri toplama bekleniyor: %.1fs", timeout)
        start = time.monotonic()

        while (time.monotonic() - start) < timeout:
            if self._session is None:
                # Session detach olmus -- process sonlandi
                logger.info("Session detach oldu, wait erken bitiyor.")
                break
            time.sleep(0.1)  # 100ms polling

        elapsed = time.monotonic() - start
        logger.info(
            "Frida wait tamamlandi: %.1fs, %d mesaj, %d hata",
            elapsed, len(self._messages), len(self._errors),
        )
