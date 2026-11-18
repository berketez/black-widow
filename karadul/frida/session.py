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

    Spawn akışı (GHIDRA-11, 2026-11-18): hedef askıda (suspended) başlatılır,
    kancalar yüklenir, ANCAK ondan sonra ``resume()`` ile sürdürülür; toplama
    bitince spawn edilen süreç ``kill()`` ile öldürülür. ``detach()`` spawn
    edilmiş ve hâlâ öldürülmemiş bir süreç bırakmaz (her çıkış yolunda öldürür).
    ``attach()`` ile bağlanılan, bizim başlatmadığımız süreç öldürülmez.

    Kullanim:
        config = Config()
        session = FridaSession(config)
        try:
            pid = session.spawn("/usr/local/bin/node", args=["app.js"])  # askıda
            session.load_script(Path("hooks/nodejs_hooks.js"))
            session.resume()
            elapsed = session.wait(timeout=10.0)
            messages = session.messages
            session.kill()
        finally:
            session.detach()   # öldürülmemiş spawn süreci kalmaz

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
        # Bizim spawn ettiğimiz ve henüz öldürülmemiş süreç (attach'te None).
        self._spawned_pid: int | None = None
        self._resumed = False
        # Oturum Frida tarafında koptu mu (süreç kendiliğinden bitti / çöktü).
        self._detached_event = threading.Event()
        self._detach_reason: str | None = None

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
            self._detached_event.clear()
            self._detach_reason = None
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
        """Yeni process'i ASKIDA spawn et ve attach et (sürdürmez).

        Süreç ilk komutunu çalıştırmadan durur. Kancalar ``load_script`` ile
        yüklendikten sonra ``resume()`` çağrılmalıdır; böylece başlangıç
        davranışı (kalıcılık, ilk bağlantı, şifre çözme) da kaydedilir.
        Attach başarısız olursa askıdaki süreç öldürülür (yetim kalmaz).

        Args:
            program: Calistirilacak program yolu.
            args: Program argumanlari.
            env: Ortam degiskenleri.

        Returns:
            Spawn edilen process'in PID'i.

        Raises:
            FridaAttachError: Spawn veya attach basarisiz olursa.
        """
        if self._spawned_pid is not None:
            raise RuntimeError(
                f"Bu oturumda öldürülmemiş bir spawn süreci var (PID={self._spawned_pid})."
            )
        device = self._get_device()

        try:
            # Spawn argumanlari
            spawn_args = [program] + (args or [])
            spawn_kwargs: dict[str, Any] = {}
            if env:
                spawn_kwargs["env"] = env

            logger.info("Frida spawn (askıda) baslatiliyor: %s", " ".join(spawn_args))
            pid = device.spawn(spawn_args, **spawn_kwargs)
            self._pid = pid
            self._spawned_pid = pid
            self._resumed = False
            self._detached_event.clear()
            self._detach_reason = None

            # Attach -- süreç hâlâ askıda; resume() kancalar yüklendikten sonra.
            self._session = device.attach(pid)
            self._session.on("detached", self._on_detached)

            logger.info("Frida spawn basarili (askıda): PID=%d, program=%s", pid, program)
            return pid

        except frida.ExecutableNotFoundError:
            msg = f"Program bulunamadi: {program}"
            logger.error(msg)
            self._kill_spawned_quietly()
            raise FridaAttachError(msg) from None

        except Exception as exc:
            msg = f"Frida spawn hatasi: {type(exc).__name__}: {exc}"
            logger.error(msg)
            # Spawn başarılı ama attach başarısızsa süreç askıda yetim kalmasın.
            self._kill_spawned_quietly()
            raise FridaAttachError(msg) from None

    def resume(self) -> None:
        """Askıda spawn edilmiş süreci sürdür (kancalar yüklendikten SONRA).

        Raises:
            RuntimeError: Bu oturumda sürdürülecek spawn süreci yoksa.
        """
        if self._spawned_pid is None:
            raise RuntimeError("Sürdürülecek spawn süreci yok. Önce spawn() çağırın.")
        if self._resumed:
            return
        device = self._get_device()
        device.resume(self._spawned_pid)
        self._resumed = True
        logger.info("Frida spawn süreci sürdürüldü: PID=%d", self._spawned_pid)

    def kill(self) -> bool:
        """Bu oturumun spawn ettiği süreci öldür.

        ``attach()`` ile bağlanılan süreç bizim değildir, öldürülmez.

        Returns:
            True: öldürme çağrısı başarılı ya da süreç zaten bitmiş.
            False: öldürülecek spawn süreci yok.

        Raises:
            RuntimeError: Süreç öldürülemediyse (çağıran bunu hata olarak
                göstermeli; hedef hâlâ çalışıyor olabilir).
        """
        pid = self._spawned_pid
        if pid is None:
            return False
        device = self._get_device()
        try:
            device.kill(pid)
            logger.info("Frida spawn süreci öldürüldü: PID=%d", pid)
        except Exception as exc:
            not_found = getattr(frida, "ProcessNotFoundError", None)
            if not_found is not None and isinstance(exc, not_found):
                logger.info("Frida spawn süreci zaten bitmiş: PID=%d", pid)
            else:
                raise RuntimeError(
                    f"Hedef süreç öldürülemedi (PID={pid}): {type(exc).__name__}: {exc}"
                ) from exc
        self._spawned_pid = None
        return True

    def _kill_spawned_quietly(self) -> None:
        """Hata yolunda spawn sürecini öldür; öldürülemezse yüksek sesle günlükle."""
        try:
            self.kill()
        except Exception as exc:
            logger.error("Spawn süreci temizlenemedi: %s", exc)

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
        """Spawn süreci varsa öldür, scriptleri unload et, oturumu kapat.

        Öldürme oturum ayrılmadan ÖNCE yapılır: kancasız ve gözetimsiz
        çalışma penceresi bırakılmaz. Öldürme başarısızsa hata günlüğe
        yazılır ve yeniden fırlatılır (sessiz yutma yok); scriptler ve oturum
        yine de kapatılır.
        """
        kill_error: Exception | None = None
        if self._spawned_pid is not None:
            try:
                self.kill()
            except Exception as exc:
                logger.error("detach: spawn süreci öldürülemedi: %s", exc)
                kill_error = exc

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
        if kill_error is not None:
            raise kill_error

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
        """Session detach callback'i (Frida iş parçacığından çağrılır)."""
        logger.info("Frida session detach oldu: reason=%s", reason)
        if crash:
            logger.warning("Process crash: %s", crash)
        self._detach_reason = str(reason)
        self._detached_event.set()

    @property
    def detach_reason(self) -> str | None:
        """Frida'nın bildirdiği kopma nedeni (ör. ``process-terminated``); kopmadıysa None."""
        return self._detach_reason

    @property
    def spawned_pid(self) -> int | None:
        """Bu oturumun spawn edip henüz öldürmediği süreç (yoksa None)."""
        return self._spawned_pid

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

    def wait(self, timeout: float | None = None) -> float:
        """Belirtilen sure boyunca veri topla.

        Process'in mesaj gondermesi icin bekler. Process erken sonlanirsa
        (Frida ``detached`` olayı) ya da oturum kapatıldıysa erken doner.

        Args:
            timeout: Bekleme suresi (saniye). None ise config'deki
                     frida_attach timeout'u kullanilir.

        Returns:
            Gerçekten beklenen süre (saniye).
        """
        if timeout is None:
            timeout = float(self.config.timeouts.frida_attach)

        logger.info("Frida veri toplama bekleniyor: %.1fs", timeout)
        start = time.monotonic()

        while (time.monotonic() - start) < timeout:
            if self._session is None or self._detached_event.is_set():
                # Session detach olmus -- process sonlandi
                logger.info("Session detach oldu, wait erken bitiyor.")
                break
            self._detached_event.wait(0.1)  # 100ms polling

        elapsed = time.monotonic() - start
        logger.info(
            "Frida wait tamamlandi: %.1fs, %d mesaj, %d hata",
            elapsed, len(self._messages), len(self._errors),
        )
        return elapsed
