"""lief native crash koruma — subprocess izolasyon sarmalayicisi.

`lief` kutuphanesi C++ tabanli native bir parser'dir. Bozuk (malformed)
veya kasitli zararli bir binary, `lief.parse()` cagrisini SIGSEGV /
abort ile dogrudan oldurebilir. Bu durum tum karadul pipeline'ini
cokertir.

Cozum: lief cagrilarini ayri bir Python subprocess'i icinde calistir.
Cocuk process crash olursa parent etkilenmez; non-zero exit kodu veya
timeout durumunda `None` doneriz.

Tasarim notu (Codex onerisi, 2026-04-26):
    `multiprocessing` Windows'ta spawn/pickle/import problemleri
    yaratabilir; `signal.alarm` POSIX-only. `subprocess.run` + JSON IPC
    her platformda ayni davranisi verir, en saglam secenektir.

Kullanim:
    from karadul.utils.lief_subprocess import parse_in_subprocess
    result = parse_in_subprocess(Path("/bin/ls"), timeout=30)
    if result is None:
        # crash, timeout, lief yok veya parse hatasi
        ...
    else:
        print(result["format"], result["sections"])

Donen sozluk yapisi (LiefParseResult):
    {
        "path": str,
        "format": str,            # "PE", "ELF", "MACHO", ...
        "sections": list[str],    # section adlari
        "segments": list[str],    # segment adlari (Mach-O icin)
        "imports": list[str],     # imported fonksiyon adlari
        "exports": list[str],     # exported fonksiyon adlari
    }
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

LiefParseResult = Dict[str, Any]

# Cocuk process'te calistirilacak worker. lief cagrisi burada yapilir;
# crash olursa sadece bu process oler, parent etkilenmez.
_WORKER_SOURCE = r"""
import json
import sys

try:
    import lief  # type: ignore
except ImportError:
    print(json.dumps({"__error__": "lief_not_installed"}))
    sys.exit(2)

try:
    payload = json.load(sys.stdin)
    path = payload["path"]
except Exception as exc:  # noqa: BLE001
    print(json.dumps({"__error__": "bad_input", "msg": str(exc)}))
    sys.exit(3)

try:
    binary = lief.parse(path)
except Exception as exc:  # noqa: BLE001
    print(json.dumps({"__error__": "parse_exception", "msg": str(exc)}))
    sys.exit(4)

if binary is None:
    print(json.dumps({"__error__": "parse_returned_none"}))
    sys.exit(0)


def _name_of(obj):
    n = getattr(obj, "name", None)
    if isinstance(n, bytes):
        try:
            return n.decode("utf-8", errors="replace")
        except Exception:
            return repr(n)
    if n is None:
        return ""
    return str(n)


fmt_attr = getattr(binary, "format", None)
fmt = getattr(fmt_attr, "name", None) or (str(fmt_attr) if fmt_attr is not None else "")

sections = []
for s in getattr(binary, "sections", []) or []:
    try:
        sections.append(_name_of(s))
    except Exception:
        continue

segments = []
for seg in getattr(binary, "segments", []) or []:
    try:
        segments.append(_name_of(seg))
    except Exception:
        continue

imports = []
for imp in getattr(binary, "imported_functions", []) or []:
    try:
        imports.append(_name_of(imp) or str(imp))
    except Exception:
        continue
if not imports:
    for sym in getattr(binary, "imported_symbols", []) or []:
        try:
            imports.append(_name_of(sym) or str(sym))
        except Exception:
            continue

exports = []
for exp in getattr(binary, "exported_functions", []) or []:
    try:
        exports.append(_name_of(exp) or str(exp))
    except Exception:
        continue

print(json.dumps({
    "path": path,
    "format": fmt,
    "sections": sections,
    "segments": segments,
    "imports": imports,
    "exports": exports,
}))
"""


def parse_bytes_in_subprocess(
    data: bytes,
    timeout: int = 30,
    max_size_mb: int = 512,
) -> Optional[LiefParseResult]:
    """`data: bytes` icin subprocess izole lief.parse sarmalayicisi.

    Veriyi gecici dosyaya yazar ve `parse_in_subprocess` cagirir.
    Caller'in dosya yolu yoksa kullanilir (ornek: bellekten gelen
    binary, packed extracted segment).
    """
    import tempfile
    if not data or len(data) > max_size_mb * 1024 * 1024:
        return None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="karadul_lief_", delete=False
        ) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
    except OSError as exc:
        logger.warning("lief_subprocess: tempfile yazilamadi: %s", exc)
        return None
    try:
        return parse_in_subprocess(tmp_path, timeout=timeout, max_size_mb=max_size_mb)
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def parse_in_subprocess(
    path: Path,
    timeout: int = 30,
    max_size_mb: int = 512,
) -> Optional[LiefParseResult]:
    """lief.parse'i ayri bir process icinde guvenli sekilde cagir.

    Args:
        path: Parse edilecek binary dosyasinin yolu.
        timeout: Cocuk process icin saniye cinsinden zaman asimi.
        max_size_mb: Bu boyutu asan dosyalar icin parse denemesi yapilmaz
            (None doner). Cok buyuk dosyalar pipeline icin risklidir.

    Returns:
        Parse sonucu sozlugu, veya hata/timeout/crash durumunda None.
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        logger.debug("lief_subprocess: dosya yok veya regular file degil: %s", p)
        return None

    try:
        size = p.stat().st_size
    except OSError:
        return None
    if size <= 0 or size > max_size_mb * 1024 * 1024:
        logger.debug(
            "lief_subprocess: dosya boyutu (%d) limit disinda, atlaniyor: %s",
            size,
            p,
        )
        return None

    try:
        completed = subprocess.run(
            [sys.executable, "-c", _WORKER_SOURCE],
            input=json.dumps({"path": str(p)}),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("lief_subprocess: timeout (%ds): %s", timeout, p)
        return None
    except OSError as exc:
        logger.warning("lief_subprocess: process baslatilamadi: %s (%s)", p, exc)
        return None

    if completed.returncode < 0:
        # Negatif kod = sinyal ile oldurulmus (SIGSEGV/SIGABRT)
        logger.warning(
            "lief_subprocess: cocuk process sinyalle oldu (signal=%d): %s",
            -completed.returncode,
            p,
        )
        return None

    if completed.returncode != 0:
        logger.debug(
            "lief_subprocess: non-zero exit (%d) %s | stderr=%s",
            completed.returncode,
            p,
            completed.stderr[:200] if completed.stderr else "",
        )
        return None

    out = (completed.stdout or "").strip()
    if not out:
        return None

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        logger.warning("lief_subprocess: gecersiz JSON cikti: %s", p)
        return None

    if isinstance(data, dict) and "__error__" in data:
        logger.debug(
            "lief_subprocess: worker hatasi (%s) %s",
            data.get("__error__"),
            p,
        )
        return None

    if not isinstance(data, dict):
        return None
    return data
