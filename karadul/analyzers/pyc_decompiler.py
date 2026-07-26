"""Python ``.pyc`` deterministik decompile motoru.

PyInstaller/cx_Freeze extraction sonrasi ortaya cikan ``.pyc`` dosyalarini
okunabilir ``.py`` kaynagina cevirir. LLM/ML KULLANMAZ (feedback_no_llm):
yalnizca deterministik, harici arac tabanli katmanli zincir.

Zincir (ilk basarili kazanir):
    1. pycdc (Decompyle++)  -- en genis deterministik decompiler, versiyon-bagimsiz
    2. decompyle3/uncompyle6 -- opsiyonel pip, yalniz Python < 3.10 icin
    3. disassembly fallback  -- pycdas (varsa) veya stdlib ``dis`` (ayni surumde)
    4. hicbiri yoksa         -- header onarilmis ``.pyc`` + acik not

KRITIK: PyInstaller ``.pyc`` header'ini (magic + timestamp) siyirir. Decompiler'lar
header olmadan "Bad MAGIC" verip patlar. ``repair_pyc_header`` bunu onarir.

Not: Modern Python bir bilgisel tavandir -- hicbir deterministik arac 3.11/3.12/3.13'u
tam cozmez. Gercekci: 3.8-3.9 tam, 3.10-3.11 kismi, 3.12+ disassembly fallback.
"""

from __future__ import annotations

import logging
import marshal
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from karadul.core.safe_subprocess import resolve_tool, safe_run

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# .pyc magic tablolari -- TEK KAYNAK (CLAUDE.md #11 magic-number tutarliligi).
# python_binary.py bu tabloyu buradan import eder.
# CPython importlib/_bootstrap_external.py MAGIC_NUMBER'dan turetilmistir.
# ---------------------------------------------------------------------------

_PYC_MAGIC_TO_VERSION: dict[int, str] = {
    # Python 3.7
    3390: "3.7", 3391: "3.7", 3392: "3.7", 3393: "3.7", 3394: "3.7",
    # Python 3.8
    3400: "3.8", 3401: "3.8", 3410: "3.8", 3411: "3.8", 3412: "3.8", 3413: "3.8",
    # Python 3.9
    3420: "3.9", 3421: "3.9", 3422: "3.9", 3423: "3.9", 3424: "3.9", 3425: "3.9",
    # Python 3.10
    3430: "3.10", 3431: "3.10", 3432: "3.10", 3433: "3.10", 3434: "3.10",
    3435: "3.10", 3436: "3.10", 3437: "3.10", 3438: "3.10", 3439: "3.10",
    # Python 3.11
    3450: "3.11", 3451: "3.11", 3452: "3.11", 3453: "3.11", 3454: "3.11",
    3455: "3.11", 3456: "3.11", 3457: "3.11", 3458: "3.11", 3459: "3.11",
    3460: "3.11", 3461: "3.11", 3462: "3.11", 3463: "3.11", 3464: "3.11",
    3465: "3.11", 3466: "3.11", 3467: "3.11", 3468: "3.11", 3469: "3.11",
    3470: "3.11", 3471: "3.11", 3472: "3.11", 3473: "3.11", 3474: "3.11",
    3475: "3.11", 3476: "3.11", 3477: "3.11", 3478: "3.11", 3479: "3.11",
    3480: "3.11", 3481: "3.11", 3482: "3.11", 3483: "3.11", 3484: "3.11",
    3485: "3.11", 3486: "3.11", 3487: "3.11", 3488: "3.11", 3489: "3.11",
    3490: "3.11", 3491: "3.11", 3492: "3.11", 3493: "3.11", 3494: "3.11",
    3495: "3.11",
    # Python 3.12
    3500: "3.12", 3501: "3.12", 3502: "3.12", 3503: "3.12", 3504: "3.12",
    3505: "3.12", 3506: "3.12", 3507: "3.12", 3508: "3.12", 3509: "3.12",
    3510: "3.12", 3511: "3.12", 3512: "3.12", 3513: "3.12", 3514: "3.12",
    3515: "3.12", 3516: "3.12", 3517: "3.12", 3518: "3.12", 3519: "3.12",
    3520: "3.12", 3521: "3.12", 3522: "3.12", 3523: "3.12", 3524: "3.12",
    3525: "3.12", 3526: "3.12", 3527: "3.12", 3528: "3.12", 3529: "3.12",
    3530: "3.12", 3531: "3.12",
    # Python 3.13
    3550: "3.13", 3551: "3.13", 3552: "3.13", 3553: "3.13", 3554: "3.13",
    3555: "3.13", 3556: "3.13", 3557: "3.13", 3558: "3.13", 3559: "3.13",
    3560: "3.13", 3561: "3.13", 3562: "3.13", 3563: "3.13", 3564: "3.13",
    3565: "3.13", 3566: "3.13", 3567: "3.13", 3568: "3.13", 3569: "3.13",
    3570: "3.13", 3571: "3.13", 3572: "3.13",
}

# Versiyon -> kanonik (final release) magic int. Header onariminda kullanilir.
# Her deger _PYC_MAGIC_TO_VERSION'da ayni versiyona map olmali (bkz. tutarlilik testi).
_VERSION_TO_MAGIC: dict[str, int] = {
    "3.7": 3394,
    "3.8": 3413,
    "3.9": 3425,
    "3.10": 3439,
    "3.11": 3495,
    "3.12": 3531,
    "3.13": 3571,
}

# .pyc header boyutu: Python 3.7+ = 16 byte (magic 4 + bit_field 4 + timestamp 4 + size 4).
_PYC_HEADER_SIZE_37 = 16
_MAGIC_TAIL = b"\r\n"  # 0x0d 0x0a -- tum gecerli .pyc magic'leri bununla biter.


def magic_bytes_for_version(py_version: str) -> Optional[bytes]:
    """Versiyon string'inden ('3.11' veya '3.11.4') 4-byte .pyc magic uret.

    Returns:
        4-byte magic (``<magic_int LE> + b'\\r\\n'``) veya None (bilinmeyen surum).
    """
    if not py_version:
        return None
    # "3.11.4" -> "3.11"
    parts = py_version.split(".")
    if len(parts) >= 2:
        key = f"{parts[0]}.{parts[1]}"
    else:
        key = py_version
    magic_int = _VERSION_TO_MAGIC.get(key)
    if magic_int is None:
        return None
    return struct.pack("<H", magic_int) + _MAGIC_TAIL


def has_valid_pyc_header(body: bytes) -> bool:
    """body zaten gecerli bir .pyc header'i (magic + \\r\\n) tasiyor mu?

    Gecerli = ilk 2 byte bilinen bir magic int + [2:4] == b'\\r\\n'.
    PyInstaller stripped .pyc'lerde body dogrudan marshal verisiyle baslar
    (tip kodu 0x63='c' / 0xe3), bu durumda False doner -> onarim tetiklenir.
    """
    if len(body) < 4:
        return False
    if body[2:4] != _MAGIC_TAIL:
        return False
    magic_int = struct.unpack("<H", body[0:2])[0]
    return magic_int in _PYC_MAGIC_TO_VERSION


def repair_pyc_header(body: bytes, py_version: Optional[str]) -> Optional[bytes]:
    """Header'i siyrilmis .pyc'ye gecerli 16-byte (3.7+) header ekle.

    - body zaten gecerli header tasiyorsa: DEGISTIRMEDEN dondur (idempotent).
    - Header yok + py_version biliniyorsa: kanonik magic + bit_field=0 +
      timestamp=0 + size=0 header'i onune ekle.
    - py_version bilinmiyor ve header yoksa: None (onarilamaz).

    Args:
        body: Ham .pyc icerigi (header'li veya header'siz).
        py_version: '3.11' / '3.11.4' gibi. None ise ve header yoksa onarim yok.

    Returns:
        Onarilmis (veya degistirilmemis) .pyc byte'lari, ya da None.
    """
    if has_valid_pyc_header(body):
        return body
    magic = magic_bytes_for_version(py_version) if py_version else None
    if magic is None:
        return None
    # 3.7+ header: magic(4) + bit_field(4)=0 + timestamp(4)=0 + source_size(4)=0.
    # bit_field=0 -> timestamp-tabanli (hash degil); decompiler'lar kabul eder.
    header = magic + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<I", 0)
    assert len(header) == _PYC_HEADER_SIZE_37
    return header + body


def version_from_pyc_bytes(body: bytes) -> Optional[str]:
    """Gecerli header tasiyan .pyc'den Python surumunu oku (magic -> versiyon)."""
    if not has_valid_pyc_header(body):
        return None
    magic_int = struct.unpack("<H", body[0:2])[0]
    return _PYC_MAGIC_TO_VERSION.get(magic_int)


# ---------------------------------------------------------------------------
# Decompile sonucu
# ---------------------------------------------------------------------------

@dataclass
class DecompileResult:
    """Tek bir .pyc icin decompile sonucu."""

    source_path: Path              # girdi .pyc
    success: bool = False          # gercek kaynak (.py) uretildi mi
    method: str = "none"           # pycdc | decompyle3 | uncompyle6 | disasm | none
    output_path: Optional[Path] = None
    error: Optional[str] = None
    is_disassembly: bool = False   # True ise cikti kaynak degil, bytecode disasm


# ---------------------------------------------------------------------------
# Decompile katmanlari
# ---------------------------------------------------------------------------

def _decompile_with_pycdc(
    pyc_path: Path,
    *,
    timeout: float,
    extra_paths: Optional[Sequence[str]] = None,
) -> Optional[str]:
    """pycdc (Decompyle++) ile decompile. Basarili ise uretilen kaynagi dondur.

    pycdc bulunamazsa veya bos/hatali cikti verirse None doner (caller fallback'e gecer).
    """
    pycdc = resolve_tool("pycdc", extra_paths=extra_paths)
    if pycdc is None:
        return None
    try:
        proc = safe_run(
            [pycdc, str(pyc_path)],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception as exc:  # TimeoutExpired dahil
        logger.debug("pycdc calistirma hatasi (%s): %s", pyc_path.name, exc)
        return None
    src = proc.stdout or ""
    # pycdc basarisizlikta stderr'e "Unsupported opcode" yazar ve/veya bos/eksik kaynak uretir.
    # Yalniz anlamli govde varsa basarili say (yorumdan ibaret cikti reddedilir).
    meaningful = [
        ln for ln in src.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if proc.returncode == 0 and meaningful:
        return src
    logger.debug(
        "pycdc anlamli kaynak uretemedi (%s): rc=%s stderr=%.200s",
        pyc_path.name, proc.returncode, proc.stderr or "",
    )
    return None


def _decompile_with_pylib(
    pyc_path: Path, py_version: Optional[str],
) -> Optional[tuple[str, str]]:
    """decompyle3/uncompyle6 (opsiyonel pip) ile decompile. Yalniz Python < 3.10.

    Bu kutuphaneler 3.10+ desteklemez; guvenli tarafta kalmak icin surum bilinip
    < 3.10 oldugunda denenir. Kurulu degilse None.
    """
    if py_version:
        parts = py_version.split(".")
        try:
            major, minor = int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            major, minor = 0, 0
        if (major, minor) >= (3, 10):
            return None  # bu araclar 3.10+ decompile edemez
    import io
    for mod_name in ("decompyle3", "uncompyle6"):
        try:
            mod = __import__(mod_name)
        except ImportError:
            continue
        try:
            buf = io.StringIO()
            # Her iki kutuphane de decompile_file(path, out) API'sini saglar.
            mod.decompile_file(str(pyc_path), buf)
            src = buf.getvalue()
            if src.strip():
                return src, mod_name
        except Exception as exc:
            logger.debug("%s decompile hatasi (%s): %s", mod_name, pyc_path.name, exc)
            continue
    return None


def _disassemble(pyc_path: Path, py_version: Optional[str], *, timeout: float) -> Optional[tuple[str, str]]:
    """Son care: bytecode disassembly. (metin, yontem) dondur veya None.

    1. pycdas (Decompyle++ disassembler) -- versiyon-bagimsiz, tercih edilir.
    2. stdlib ``dis`` -- yalniz .pyc surumu CALISAN Python ile uyumluysa
       (marshal.loads farkli bytecode surumunde patlar).
    """
    # 1. pycdas
    pycdas = resolve_tool("pycdas")
    if pycdas is not None:
        try:
            proc = safe_run(
                [pycdas, str(pyc_path)],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0 and (proc.stdout or "").strip():
                return proc.stdout, "disasm"
        except Exception as exc:
            logger.debug("pycdas hatasi (%s): %s", pyc_path.name, exc)

    # 2. stdlib dis (yalniz .pyc surumu CALISAN Python ile ayni major.minor ise)
    try:
        import dis
        import io
        import sys
        running = f"{sys.version_info.major}.{sys.version_info.minor}"
        if py_version:
            pv_parts = py_version.split(".")
            pv_mm = ".".join(pv_parts[:2]) if len(pv_parts) >= 2 else py_version
            if pv_mm != running:
                return None  # surum uyusmuyor -> marshal.loads guvenilmez
        body = pyc_path.read_bytes()
        if not has_valid_pyc_header(body):
            return None
        code = marshal.loads(body[_PYC_HEADER_SIZE_37:])
        buf = io.StringIO()
        dis.dis(code, file=buf)
        text = buf.getvalue()
        if text.strip():
            return text, "disasm"
    except Exception as exc:
        logger.debug("stdlib dis hatasi (%s): %s", pyc_path.name, exc)
    return None


def decompile_pyc(
    pyc_path: Path,
    out_dir: Path,
    *,
    py_version: Optional[str] = None,
    timeout: float = 120.0,
    extra_paths: Optional[Sequence[str]] = None,
) -> DecompileResult:
    """Tek bir (header'i gecerli) .pyc'yi decompile et.

    pyc_path'in header'i onarilmis olmali (bkz. repair_pyc_header). py_version
    verilmezse header'daki magic'ten okunur.

    Katmanli: pycdc -> decompyle3/uncompyle6 -> disassembly -> none.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    result = DecompileResult(source_path=pyc_path)

    body = pyc_path.read_bytes()
    if py_version is None:
        py_version = version_from_pyc_bytes(body)

    stem = pyc_path.stem
    py_out = out_dir / f"{stem}.py"

    # 1. pycdc
    src = _decompile_with_pycdc(pyc_path, timeout=timeout, extra_paths=extra_paths)
    if src is not None:
        py_out.write_text(src, encoding="utf-8", errors="replace")
        result.success = True
        result.method = "pycdc"
        result.output_path = py_out
        return result

    # 2. decompyle3 / uncompyle6 (opsiyonel, < 3.10)
    pylib = _decompile_with_pylib(pyc_path, py_version)
    if pylib is not None:
        src, method = pylib
        py_out.write_text(src, encoding="utf-8", errors="replace")
        result.success = True
        result.method = method
        result.output_path = py_out
        return result

    # 3. disassembly fallback
    disasm = _disassemble(pyc_path, py_version, timeout=timeout)
    if disasm is not None:
        text, method = disasm
        disasm_out = out_dir / f"{stem}.disasm.txt"
        disasm_out.write_text(text, encoding="utf-8", errors="replace")
        result.success = False       # kaynak degil; kismi kurtarma
        result.method = method
        result.output_path = disasm_out
        result.is_disassembly = True
        return result

    # 4. hicbiri
    result.method = "none"
    result.error = "hicbir decompiler/disassembler basarili olmadi"
    return result


def decompile_all(
    pyc_paths: Sequence[Path],
    out_dir: Path,
    *,
    py_version: Optional[str] = None,
    timeout: float = 120.0,
    extra_paths: Optional[Sequence[str]] = None,
) -> list[DecompileResult]:
    """Bir grup .pyc'yi decompile et. Her biri icin DecompileResult dondur.

    Not: pyc_paths'in header'lari onarilmis olmali. Onarim caller'da (python_binary
    reconstruct) yapilir; burada dogrudan decompile edilir.
    """
    results: list[DecompileResult] = []
    for p in pyc_paths:
        try:
            results.append(
                decompile_pyc(
                    p, out_dir, py_version=py_version, timeout=timeout,
                    extra_paths=extra_paths,
                )
            )
        except Exception as exc:
            logger.debug("decompile_pyc beklenmedik hata (%s): %s", p, exc)
            r = DecompileResult(source_path=p, method="none", error=str(exc))
            results.append(r)
    return results
