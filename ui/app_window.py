"""Black Widow — native macOS pencere (pywebview / WKWebView).

UI'ı TARAYICI yerine gerçek bir uygulama penceresinde açar. ``ui/server.py``'yi
alt-süreç olarak başlatır (env'i miras alır: GHIDRA_INSTALL_DIR, KARADUL_DATA_DIR,
JAVA_HOME), yanıt vermesini bekler, sonra WKWebView penceresini açar. Pencere
kapanınca server sonlandırılır ve uygulama kapanır. .app launcher bunu exec eder.
"""
from __future__ import annotations

import atexit
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# Sabit 8000 iki şekilde kırılıyordu: (1) portta başka bir HTTP servisi varsa
# pencere onun arayüzünü açıyordu, (2) eski bir öksüz server'a bağlanıyordu.
# Artık boş port seçilir ve kimlik jetonuyla "bizim server" doğrulanır.
PORT = int(os.environ["KARADUL_PORT"]) if os.environ.get("KARADUL_PORT") else _free_port()
TOKEN = os.environ.get("KARADUL_TOKEN") or secrets.token_hex(16)
os.environ["KARADUL_PORT"] = str(PORT)
os.environ["KARADUL_TOKEN"] = TOKEN
URL = f"http://127.0.0.1:{PORT}"


def _up() -> bool:
    """Yalnızca BİZİM server'ımız için True (yabancı/öksüz servis eşleşmesin)."""
    try:
        with urllib.request.urlopen(f"{URL}/api/ping", timeout=1) as r:
            return json.load(r).get("token") == TOKEN
    except Exception:
        return False


def main() -> int:
    proc: subprocess.Popen | None = None
    if not _up():
        data_dir = Path(os.environ.get("KARADUL_DATA_DIR") or HERE.parent)
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            log = open(data_dir / "ui.log", "w")
        except OSError:
            log = subprocess.DEVNULL  # type: ignore[assignment]
        proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdout=log, stderr=subprocess.STDOUT, env=os.environ.copy(),
            # Kendi süreç grubu -> kapanışta tüm ağacı killpg ile götürebilelim.
            # start_new_session DEĞİL: posix_spawn setsid'i desteklemediğinden
            # Python fork_exec'e düşer ve macOS'ta fork deadlock riski doğar.
            process_group=0,
        )

        def _shutdown(_p: subprocess.Popen = proc) -> None:
            """Server'ı VE altındaki analiz/JVM ağacını götür.

            terminate() yalnız server'a SIGTERM atıyordu; ``karadul analyze`` ve
            Ghidra JVM onun çocukları -> öksüz kalıp saatlerce CPU yiyorlardı.
            atexit: pywebview kapanışında ``finally`` her zaman unwind edilmiyor.
            """
            if _p.poll() is not None:
                return
            try:
                os.killpg(os.getpgid(_p.pid), signal.SIGTERM)
                _p.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(os.getpgid(_p.pid), signal.SIGKILL)
                except Exception:
                    pass

        atexit.register(_shutdown)

        for _ in range(80):          # ~24 sn: Ghidra'sız server anında kalkar
            if _up():
                break
            if proc.poll() is not None:   # server öldü (ör. port bind hatası)
                sys.stderr.write("server başlatılamadı; ui.log'a bakın\n")
                return 1
            time.sleep(0.3)
        else:
            sys.stderr.write("server zamanında yanıt vermedi; ui.log'a bakın\n")

    import webview  # pywebview -> macOS'ta WKWebView (pyobjc)

    webview.create_window(
        "Black Widow",
        URL,
        width=1280,
        height=840,
        min_size=(960, 640),
        background_color="#06080d",   # Black Widow koyu tema (beyaz flash olmasın)
    )
    webview.start()                   # Cocoa event loop -- pencere kapanana kadar bloklar
    return 0                          # temizlik atexit ile (finally atlanabiliyor)


if __name__ == "__main__":
    sys.exit(main())
