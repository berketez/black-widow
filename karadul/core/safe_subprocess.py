"""Guvenli subprocess yardimcilari (v1.10.0 Batch 5B -- PATH hijack mitigation).

Bu modul Red Team 2. tur bulgularindan dogdu. Kapsam: **PATH hijack** ve
**LD_PRELOAD/DYLD injection** vektorlerini azaltmak.

1. ``resolve_tool(name)``: ``shutil.which()`` yerine yalnizca whitelist path'lerden
   arac arar. $PATH icinde `malicious/bin/upx` dursa bile tespit edilmez.
2. ``safe_env(extra)``: LD_PRELOAD, DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH gibi
   injection env'lerini BARINDIRMAZ. JAVA_TOOL_OPTIONS ile Log4Shell kapali.
3. ``safe_run(cmd, ...)``: ``subprocess.run`` cagrisini varsayilan ``env=safe_env()``
   ile sarar ve `shell=False` zorunlu kilar.

Her subprocess yolu bu modulden gecmeli. Eski ``subprocess.run(cmd)`` cagrilari
kaldirilmiyor (migrate kapsami disindaki yollar mevcut env'i kullanmaya devam
eder) ancak harici arac cagrilari (upx, jadx, nm, otool, strings, node, npm,
capa, decompyle3 vb.) buraya tasindi.

NOT (guvenlik kapsami):
    Whitelist path'lerdeki (ozellikle ``/opt/homebrew/bin``, ``/usr/local/bin``)
    dosyalar root-only DEGILDIR; macOS'ta Homebrew ve pek cok kurulum
    kullanici-yonetimli root altindadir. Saldirgan bu dizinlerde bir yazma
    hakki kazanirsa whitelist bypass olur. Bu modul **PATH hijack** ve
    **LD_PRELOAD/DYLD injection** vektorlerini azaltir; **tam supply-chain
    korumasi SAGLAMAZ** (ornek: malicious homebrew tap, symlink attack,
    compromised upstream package gibi vektorleri adreslemez). Tam kapsam
    icin paket imzasi, read-only FS, veya sandboxing gereklidir.

CWE referanslari:
- CWE-426 (Untrusted Search Path): resolve_tool whitelist
- CWE-427 (Uncontrolled Search Path Element): aynisi
- CWE-114 (Process Control via LD_PRELOAD): safe_env whitelist
- CWE-78 (OS Command Injection): shell=False zorunlu
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Whitelist yollari -- SADECE OS-kurulu dizinlerden arac ara.
# ---------------------------------------------------------------------------
# $PATH'te `.local/bin`, CWD, `$HOME/bin` gibi attacker-controlled dizinler
# olabilir. Bu liste root veya package-manager tarafindan yonetilen yerleri
# kapsar. Ek path'ler gerekirse ``resolve_tool(name, extra_paths=[...])``.
_SAFE_TOOL_PATHS: tuple[str, ...] = (
    "/usr/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",      # Apple Silicon Homebrew
    "/opt/homebrew/sbin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    "/Library/Developer/CommandLineTools/usr/bin",  # Xcode CLT
)


def get_safe_tool_paths() -> tuple[str, ...]:
    """Default whitelist yollari dondurur (kopyalanmis tuple)."""
    return tuple(_SAFE_TOOL_PATHS)


def resolve_tool(
    name: str,
    *,
    extra_paths: Optional[Sequence[str]] = None,
) -> Optional[str]:
    """Bir harici araci whitelist path'lerde ara.

    ``shutil.which()`` yerine bunu kullan. ``$PATH`` icindeki attacker
    tarafindan eklenmis dizinler (ornek: ``~/.local/bin`` ile hijack edilmis
    ``upx``) tespit edilmez -- yalnizca sistem/OS-kurulu path'ler.

    Args:
        name: Arac adi (ornek: "upx", "jadx", "capa"). Path separator
            (``/``, ``\\``) iceren isimler reddedilir -- sadece dosya adi.
        extra_paths: Ek whitelist dizinler (ornek: kullanicinin verdigi
            ``--tool-path``). None varsayilan.

    Returns:
        Bulunan tam yol (string) veya None.

    Guvenlik notlari:
        - ``name`` icinde ``/`` veya ``..`` olursa None. Caller'in bunu
          ad sanip path acmaya calismasini engeller.
        - Symlink'ler kabul edilir, ancak final dosya executable olmali
          ve ``is_file()`` returnlenmeli (device/fifo reddedilir).
        - Permission check ``os.access(..., X_OK)`` ile yapilir.
    """
    if not name or "/" in name or "\\" in name or ".." in name:
        logger.warning("resolve_tool: gecersiz arac adi reddedildi: %r", name)
        return None

    paths: list[str] = list(_SAFE_TOOL_PATHS)
    if extra_paths:
        for p in extra_paths:
            # extra_paths da resolve edilmis absolute olmali
            try:
                resolved = str(Path(p).resolve())
                if resolved not in paths:
                    paths.append(resolved)
            except (OSError, RuntimeError):
                logger.debug("extra_paths resolve basarisiz: %s", p)

    for d in paths:
        candidate = Path(d) / name
        try:
            if candidate.is_file() and os.access(str(candidate), os.X_OK):
                return str(candidate)
        except OSError:
            continue

    return None


# ---------------------------------------------------------------------------
# Guvenli env: LD_PRELOAD, DYLD_INSERT_LIBRARIES DAHIL DEGIL.
# ---------------------------------------------------------------------------
# Parent process'te bunlar set ise cocuk process'lere inherit olur; pentest
# sirasinda malicious dylib onceden enjeke edilmis olabilir. Whitelist env
# ile yeni bir base olusturup yalnizca beklenen degerleri iletiriz.

# JAVA_TOOL_OPTIONS: Log4Shell (CVE-2021-44228) ve Log4j2 lookup'larini devre
# disi birakir. jadx, Ghidra, bsim gibi JVM araclari icin global switch.
_JAVA_SAFE_OPTS = "-Dlog4j2.formatMsgNoLookups=true"


def _default_safe_env_base() -> dict[str, str]:
    """Guvenli temel env. DYLD/LD injection env'lerini almaz."""
    home = os.environ.get("HOME", "/tmp")
    tmp = os.environ.get("TMPDIR", "/tmp")
    return {
        "PATH": ":".join(_SAFE_TOOL_PATHS),
        "HOME": home,
        "TMPDIR": tmp,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "JAVA_TOOL_OPTIONS": _JAVA_SAFE_OPTS,
        # Ghidra / Java: stdin buffer icin
        "JAVA_HOME": os.environ.get("JAVA_HOME", ""),
    }


# Inherit edilebilecek ama tehlikeli env'ler -- BLACKLIST.
# Bu env'ler safe_env'de kesinlikle yer almaz. passthrough=True olsa bile
# filtre uygulanir.
_BLACKLISTED_ENVS = frozenset({
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_VERSIONED_LIBRARY_PATH",
    "DYLD_VERSIONED_FRAMEWORK_PATH",
    "PYTHONPATH",           # arbitrary code import riski
    "PYTHONSTARTUP",
    "NODE_OPTIONS",         # --require malicious.js
    "PERL5OPT",
    "RUBYOPT",
})


def safe_env(
    extra: Optional[Mapping[str, str]] = None,
    *,
    passthrough: Optional[Sequence[str]] = None,
) -> dict[str, str]:
    """LD_PRELOAD-safe ortam degiskenleri olustur.

    Args:
        extra: Ek key/value'lar. Blacklist'teki isimler DOMUS EDILIR
            (warning log'lanir ama yine de reddedilir). Diger her sey eklenir.
        passthrough: Parent env'den aynen alinacak anahtar listesi (ornek:
            ["USER", "TERM"]). Blacklist filtresi yine uygulanir.

    Returns:
        Yeni dict -- subprocess.run ``env=`` parametresine dogrudan verilebilir.
    """
    env = _default_safe_env_base()

    if passthrough:
        for key in passthrough:
            if key in _BLACKLISTED_ENVS:
                logger.warning("safe_env: blacklist env passthrough reddedildi: %s", key)
                continue
            val = os.environ.get(key)
            if val is not None:
                env[key] = val

    if extra:
        for key, val in extra.items():
            if key in _BLACKLISTED_ENVS:
                logger.warning("safe_env: blacklist env extra reddedildi: %s", key)
                continue
            env[key] = str(val)

    return env


# ---------------------------------------------------------------------------
# subprocess.run sarmalayicisi.
# ---------------------------------------------------------------------------

def safe_run(
    cmd: Sequence[str],
    *,
    env: Optional[Mapping[str, str]] = None,
    env_extra: Optional[Mapping[str, str]] = None,
    timeout: Optional[float] = None,
    cwd: Optional[str | Path] = None,
    capture_output: bool = False,
    stdout: Any = None,
    stderr: Any = None,
    text: bool = True,
    check: bool = False,
    input: Optional[str | bytes] = None,
) -> subprocess.CompletedProcess:
    """`subprocess.run` sarmalayicisi.

    - ``shell=False`` zorunlu (liste verilmesi dayatilir).
    - ``env`` verilmezse ``safe_env(env_extra)`` kullanilir.
    - ``env`` verilirse blacklist env'ler temizlenir.

    Args:
        cmd: Komut ve argumanlari (liste). String argumanlar reddedilir
            (shell injection koruma).
        env: Tam ortam degiskeni haritasi. None ise safe_env().
        env_extra: Sadece safe_env tabani uzerine ek degerler.
        diger: subprocess.run ile ayni semantik.

    Returns:
        subprocess.CompletedProcess

    Raises:
        ValueError: ``cmd`` string ise veya bos ise.
        subprocess.TimeoutExpired: Timeout asilirsa.
    """
    if isinstance(cmd, (str, bytes)):
        raise ValueError(
            "safe_run: cmd liste olmali (shell injection koruma). Verilen: %r" % type(cmd)
        )
    if not cmd:
        raise ValueError("safe_run: bos cmd")

    if env is None:
        effective_env = safe_env(env_extra)
    else:
        # Dict olarak gelen env'de blacklist temizle
        effective_env = {
            k: str(v) for k, v in env.items()
            if k not in _BLACKLISTED_ENVS
        }
        # JAVA_TOOL_OPTIONS zorla Log4Shell kapali olsun
        effective_env.setdefault("JAVA_TOOL_OPTIONS", _JAVA_SAFE_OPTS)
        if env_extra:
            for k, v in env_extra.items():
                if k not in _BLACKLISTED_ENVS:
                    effective_env[k] = str(v)

    cmd_str_list = [str(c) for c in cmd]

    return subprocess.run(
        cmd_str_list,
        env=effective_env,
        timeout=timeout,
        cwd=str(cwd) if cwd else None,
        capture_output=capture_output,
        stdout=stdout,
        stderr=stderr,
        text=text,
        check=check,
        input=input,
        shell=False,
    )


# ---------------------------------------------------------------------------
# zlib bomb korumasi (streaming decompress)
# ---------------------------------------------------------------------------

def safe_zlib_decompress(
    raw: bytes,
    *,
    max_size: int,
    wbits: int = 15,
) -> Optional[bytes]:
    """Streaming zlib decompress, bomb korumali.

    `zlib.decompress(raw)` tek seferde ne kadar buyurse buyusun acmaya
    calisir -- 1KB input -> 10GB output mumkun. Bu fonksiyon ``decompressobj``
    ile parcali acar ve ``max_size`` asildigi anda ``None`` doner.

    Args:
        raw: Compressed veri.
        max_size: Byte cinsinden ust sinir (uncompressed).
        wbits: ``zlib.decompressobj`` ayari. Default 15 (standart zlib).

    Returns:
        Decompressed bytes veya None (bomb/hata).
    """
    import zlib

    try:
        decomp = zlib.decompressobj(wbits)
        # max_size+1 isteyerek tek seferde ust siniri asip asmadigini tespit et
        out = decomp.decompress(raw, max_size + 1)
        if len(out) > max_size:
            logger.warning(
                "zlib bomb: decompressed %d > max_size %d (compressed=%d)",
                len(out), max_size, len(raw),
            )
            return None
        # Unused input varsa stream duzgun bitmedi
        if decomp.unconsumed_tail:
            logger.warning(
                "zlib bomb: unconsumed_tail mevcut (len=%d)",
                len(decomp.unconsumed_tail),
            )
            return None
        # Stream kapatilabilir mi?
        tail = decomp.flush()
        if len(out) + len(tail) > max_size:
            logger.warning(
                "zlib bomb: flush sonrasi %d > max_size %d",
                len(out) + len(tail), max_size,
            )
            return None
        if not decomp.eof:
            logger.warning("zlib: decompressobj.eof False (truncated stream)")
            return None
        return out + tail
    except zlib.error as exc:
        logger.debug("zlib decompress hatasi: %s", exc)
        return None
    except MemoryError:
        logger.error("zlib decompress MemoryError -- max_size cok buyuk?")
        return None


__all__ = [
    "resolve_tool",
    "safe_env",
    "safe_run",
    "safe_zlib_decompress",
    "get_safe_tool_paths",
]
