"""Black Widow — native macOS pencere (pywebview / WKWebView).

UI'ı TARAYICI yerine gerçek bir uygulama penceresinde açar. ``ui/server.py``'yi
alt-süreç olarak başlatır (env'i miras alır: GHIDRA_INSTALL_DIR, KARADUL_DATA_DIR,
JAVA_HOME), yanıt vermesini bekler, sonra WKWebView penceresini açar. Pencere
kapanınca server sonlandırılır ve uygulama kapanır. .app launcher bunu exec eder.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"
PORT = int(os.environ.get("KARADUL_PORT", "8000"))
URL = f"http://127.0.0.1:{PORT}"


def _up() -> bool:
    try:
        with urllib.request.urlopen(URL, timeout=1):
            return True
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
        )
        for _ in range(80):          # ~24 sn: Ghidra'sız server anında kalkar
            if _up():
                break
            time.sleep(0.3)

    import webview  # pywebview -> macOS'ta WKWebView (pyobjc)

    webview.create_window(
        "Black Widow",
        URL,
        width=1280,
        height=840,
        min_size=(960, 640),
        background_color="#06080d",   # Black Widow koyu tema (beyaz flash olmasın)
    )
    try:
        webview.start()               # Cocoa event loop -- pencere kapanana kadar bloklar
    finally:
        if proc is not None:
            proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
