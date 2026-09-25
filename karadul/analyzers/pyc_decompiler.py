"""Python ``.pyc`` deterministik decompile motoru.

PyInstaller/cx_Freeze extraction sonrasi ortaya cikan ``.pyc`` dosyalarini
okunabilir ``.py`` kaynagina cevirir. LLM/ML KULLANMAZ (feedback_no_llm):
yalnizca deterministik, harici arac tabanli katmanli zincir.

Zincir (ilk basarili kazanir):
    1. pycdc (Decompyle++)  -- en genis deterministik decompiler, versiyon-bagimsiz
    2. decompyle3/uncompyle6 -- opsiyonel pip, yalniz Python < 3.10 icin (ayrı süreçte)
    3. disassembly fallback  -- pycdas (varsa) veya stdlib ``dis`` (ayni surumde)
    4. hicbiri yoksa         -- header onarilmis ``.pyc`` + acik not

KRITIK: PyInstaller ``.pyc`` header'ini (magic + timestamp) siyirir. Decompiler'lar
header olmadan "Bad MAGIC" verip patlar. ``repair_pyc_header`` bunu onarir.

pycdc çıktısı yalnız doğrulanırsa "kaynak" sayılır (bkz. ``_source_problems``):
pycdc desteklemediği opcode'da bile çıkış kodu 0 döner, çözemediği gövdeyi
``pass`` + "Decompyle incomplete" yorumuyla yazar. Doğrulanamayan çıktı atılmaz;
``<ad>.partial.py`` olarak saklanır ve zincir disassembly'ye devam eder.

Not: Modern Python bir bilgisel tavandir -- hicbir deterministik arac 3.11/3.12/3.13'u
tam cozmez. Ölçülen (pycdc b428976, 2026-09-25, PyInstaller bootstrap + küçük
script korpusu): 3.9-3.12'de dosyaların çoğu kısmi, 3.13'te fonksiyon içeren her
dosya kısmi (MAKE_FUNCTION desteklenmiyor), 3.14 hiç desteklenmiyor.
"""

from __future__ import annotations

import functools
import importlib.util
import logging
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from karadul.core.safe_subprocess import resolve_tool, safe_env

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
    success: bool = False          # doğrulanmış gerçek kaynak (.py) üretildi mi
    method: str = "none"           # pycdc | decompyle3 | uncompyle6 | disasm | <araç>_partial | none
    output_path: Optional[Path] = None
    error: Optional[str] = None
    is_disassembly: bool = False   # True ise cikti kaynak degil, bytecode disasm
    # Decompiler çıktı verdi ama doğrulanamadı (eksik/geçersiz): kaynak DEĞİL, kısmi kurtarma.
    partial_path: Optional[Path] = None    # <ad>.partial.py
    partial_reason: Optional[str] = None   # neden doğrulanamadı ("; " ile birleşik)
    # Bir aracın çıktısı alt süreç çıktı tavanında kesildi (dosyada işaret satırı var).
    truncated: bool = False


# pycdc bir kod bloğunu çözemediğinde çıktıya (girintili) bu yorumu yazar; çıkış
# kodu yine 0'dır. Bu satırı taşıyan çıktı gerçek kaynak DEĞİLDİR.
_PYCDC_INCOMPLETE_MARKER = "# WARNING: Decompyle incomplete"

# uncompyle6/decompyle3 (3.9.3 kaynaklarından doğrulandı): çözemediği bölümün yerine
# bu satırları çıktıya yazar; CLI'ları ayrıca stderr'e "# file ..." yazıp çıkış
# kodu 0 ile biter ve kısmi -o dosyasını silmez. Satırı bunlardan biriyle başlayan
# çıktı gerçek kaynak DEĞİLDİR.
_PYLIB_FAILURE_MARKERS = (
    "--- This code section failed: ---",
    "Parse error at or near",
    "# NOTE: have internal decompilation grammar errors",
    "# NOTE: have decompilation errors",
    "Deparsing stopped due to parse error",
)


# ---------------------------------------------------------------------------
# Decompile katmanlari
# ---------------------------------------------------------------------------

def _decode_tool_output(data: bytes | bytearray | str | None) -> tuple[str, Optional[str]]:
    """Harici araç çıktısını UTF-8 çöz: (metin, sorun). Geçersiz bayt U+FFFD olur.

    pycdc/pycdas string sabitlerini ham bayt olarak basar; yalnız vekil karakter
    (ör. ``'\\udcff'``) geçersiz UTF-8 üretir. Katı çözüm (``text=True``)
    UnicodeDecodeError fırlatıp çıktının TAMAMINI kaybettiriyordu.
    """
    if data is None:
        return "", None
    if isinstance(data, str):
        return data, None
    raw = bytes(data)
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        return (
            raw.decode("utf-8", errors="replace"),
            f"geçersiz UTF-8 bayt (konum {exc.start}); ilgili sabitler U+FFFD ile değiştirildi",
        )


def _partial_banner(reason: str, tool: str = "pycdc") -> str:
    """Kısmi decompiler çıktısının başına yazılan uyarı (dosya tek başına açılsa da dürüst)."""
    return (
        f"# KARADUL: {tool} çıktısı DOĞRULANAMADI -- gerçek kaynak DEĞİL (kısmi kurtarma).\n"
        f"# Neden: {reason.replace(chr(10), ' ')}\n"
        "# Tam bytecode için (varsa) aynı adlı .disasm.txt dosyasına bakın.\n\n"
    )


# Başlık satır sayısı: SyntaxError satır numarası .partial.py'deki satıra denk gelsin.
_PARTIAL_BANNER_LINES = _partial_banner("").count("\n")


def _source_problems(
    src: str, *, tool: str, returncode: int = 0, stderr: str = "",
) -> list[str]:
    """Decompiler çıktısını gerçek kaynak saymaya engel durumlar (boş liste = doğrulandı).

    pycdc, decompyle3 ve uncompyle6 (kütüphane ya da CLI) için TEK doğrulayıcı.
    pycdc desteklemediği opcode'da bile çoğunlukla rc=0 döner; çözemediği gövdeyi
    ``pass`` + "Decompyle incomplete" yorumuyla, bozuk ifadeyi geçersiz sözdizimiyle
    yazar. uncompyle6/decompyle3 çözemediği bölüme "--- This code section failed"
    bloğu yazar (``_PYLIB_FAILURE_MARKERS``). Ölçütler:

    1. rc == 0 (negatif rc = sinyalle çöküş; çıktı yarıda kesilmiştir).
    2. Aracın "çözülemedi" işareti yok.
    3. stderr boş. pycdc stderr'e yalnız sorun olunca yazar; "Warning: block stack
       is not empty!" bile ölçülen örnekte yanlış girintili ``return`` üretti
       (3.11, derlenebilir ama anlamca yanlış kod). uncompyle6/decompyle3 CLI'ı
       hatayı yalnız stderr'e yazıp 0 ile çıkar.
    4. Çıktı çalışan Python'da ``compile()`` ediliyor. Kod ÇALIŞTIRILMAZ. ast.parse
       yetmez: modül düzeyinde ``return`` (pycdc 3.10-3.12'de sık) yalnız derleyici
       aşamasında yakalanır.

    Sınır: compile() anlamı doğrulamaz. Çalışan Python .pyc sürümünden eskiyse yeni
    sözdizimi yanlış alarm verebilir; bu güvenli yöndür (kısmi sayılır, çıktı kaybolmaz).
    """
    problems: list[str] = []
    if returncode != 0:
        if returncode < 0:
            try:
                sig_name = signal.Signals(-returncode).name
            except ValueError:
                sig_name = f"sinyal {-returncode}"
            problems.append(f"{tool} çöktü ({sig_name})")
        else:
            problems.append(f"{tool} rc={returncode}")
    lines = [ln.strip() for ln in src.splitlines()]
    if tool == "pycdc":
        if _PYCDC_INCOMPLETE_MARKER in lines:
            problems.append("'Decompyle incomplete' işareti (en az bir blok çözülemedi)")
    else:
        hit = next((m for m in _PYLIB_FAILURE_MARKERS
                    if any(ln.startswith(m) for ln in lines)), None)
        if hit:
            problems.append(f"'{hit}' işareti ({tool} en az bir bölümü çözemedi)")
    err_lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
    if err_lines:
        more = f" (+{len(err_lines) - 1} satır)" if len(err_lines) > 1 else ""
        problems.append(f"{tool} stderr: {err_lines[0]}{more}")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # SyntaxWarning (geçersiz kaçış vb.) gürültüsü
            compile(src, f"<{tool}>", "exec", dont_inherit=True)
    except SyntaxError as exc:
        # Sorunlu çıktı .partial.py olarak başlıkla yazılır; satırı o dosyaya göre ver.
        line = (exc.lineno or 0) + _PARTIAL_BANNER_LINES
        problems.append(f"SyntaxError: {exc.msg} (.partial.py satır {line})")
    except Exception as exc:  # ValueError (NUL bayt), RecursionError, MemoryError
        problems.append(f"derlenemedi: {type(exc).__name__}")
    return problems


def _truncated_problem(tool: str) -> str:
    """Çıktısı alt süreç tavanında kesilen aracın sorun metni (.partial.py'de de yazılır)."""
    return f"{tool} çıktısı {_CHILD_MAX_OUTPUT_BYTES} bayt sınırında kesildi (eksik)"


def _decompile_with_pycdc(
    pyc_path: Path,
    *,
    timeout: float,
    extra_paths: Optional[Sequence[str]] = None,
) -> Optional[tuple[str, list[str], bool]]:
    """pycdc (Decompyle++) ile decompile.

    Returns:
        None: pycdc yok, çalıştırılamadı/durduruldu ya da yorum dışı hiçbir satır
        üretmedi. (kaynak, sorunlar, kesildi): ``sorunlar`` boşsa çıktı doğrulanmış
        kaynaktır; doluysa eksik/geçersizdir (çağıran kısmi çıktı olarak saklar,
        sonraki katmana geçer). Çıktı tavanında kesilen kaynak (``_run_capped``) her
        zaman kısmidir (``kesildi`` True, sorunlarda nedeni yazılı).
    """
    pycdc = resolve_tool("pycdc", extra_paths=extra_paths)
    if pycdc is None:
        return None
    run = _run_tool([pycdc, str(pyc_path)], timeout=timeout)
    if run.status not in ("ok", "truncated"):
        logger.debug("pycdc calistirilamadi/durduruldu (%s): %s", pyc_path.name, run.status)
        return None
    src, decode_problem = _decode_tool_output(run.stdout)
    stderr, _ = _decode_tool_output(run.stderr)
    # Yorumdan ibaret çıktı (yalnız "# Source Generated with Decompyle++" başlığı)
    # kısmi kurtarma bile değildir.
    meaningful = [
        ln for ln in src.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if not meaningful:
        logger.debug(
            "pycdc anlamli kaynak uretemedi (%s): rc=%s stderr=%.200s",
            pyc_path.name, run.returncode, stderr,
        )
        return None
    problems = _source_problems(
        src, tool="pycdc",
        # Bekçinin öldürdüğü sürecin rc'si yoktur; kesilme ayrıca sorun olarak yazılır.
        returncode=run.returncode if run.returncode is not None else 0,
        stderr=stderr,
    )
    truncated = run.status == "truncated"
    if truncated:
        problems.insert(0, _truncated_problem("pycdc"))
    if decode_problem:
        problems.append(decode_problem)
    return src, problems, truncated


# decompyle3/uncompyle6 (opsiyonel pip): AYRI SÜREÇTE. Eskiden kütüphane analiz
# sürecinin İÇİNDE ve zaman aşımsız çağrılıyordu: decompile_file güvenilmeyen
# .pyc'yi açar (xdis; sürüm aynıysa marshal) ve ayrıştırıcısı kötü girdide
# takılabilir -> tüm analiz asılı kalırdı. Artık dis yedeğiyle aynı kalıp
# (``_run_capped``: zaman aşımı + bellek bekçisi + çıktı tavanı). Ana süreç
# kütüphaneyi import bile etmez: yeri ``importlib.util.find_spec`` ile bulunur
# (modül kodu çalışmaz) ve bulunduğu sys.path kökü alt sürece verilir.
_PYLIB_MODULES = ("decompyle3", "uncompyle6")
_PYLIB_RC_NO_MODULE = 5
_PYLIB_RC_ERROR = 6
_PYLIB_CHILD_SCRIPT = f"""
import io, sys
path, mod_name, root, max_mem = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
try:
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (max_mem, max_mem))
except Exception:
    pass
if root not in sys.path:
    sys.path.append(root)
try:
    mod = __import__(mod_name)
except ImportError:
    sys.exit({_PYLIB_RC_NO_MODULE})
out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="backslashreplace")
try:
    mod.decompile_file(path, out)
    out.flush()
except Exception:
    sys.exit({_PYLIB_RC_ERROR})
"""


def _pylib_search_root(mod_name: str) -> Optional[str]:
    """Kütüphanenin bulunduğu sys.path kökü; kurulu değilse None. Modülü import ETMEZ."""
    try:
        spec = importlib.util.find_spec(mod_name)
    except (ImportError, ValueError):   # ValueError: sys.modules'ta __spec__'siz nesne
        return None
    if spec is None:
        return None
    locations = list(spec.submodule_search_locations or [])
    if locations:
        return str(Path(locations[0]).parent)
    if spec.origin and spec.has_location:
        return str(Path(spec.origin).parent)
    return None


def _decompile_with_pylib(
    pyc_path: Path, py_version: Optional[str], *, timeout: float,
) -> Optional[tuple[str, str, list[str], bool]]:
    """decompyle3/uncompyle6 (opsiyonel pip) ile, AYRI SÜREÇTE decompile. Yalniz Python < 3.10.

    Bu kutuphaneler 3.10+ desteklemez; guvenli tarafta kalmak icin surum bilinip
    < 3.10 oldugunda denenir. Kurulu degilse alt süreç açılmaz, None.

    Çıktı pycdc'ninkiyle aynı doğrulamadan geçer (``_source_problems``). Kütüphane
    hata verirse (rc != 0), süre/bellek sınırına takılırsa çıktısı kullanılmaz;
    çıktı tavanında kesilirse kısmi sayılır. Returns: (kaynak, araç, sorunlar,
    kesildi) -- ilk doğrulanan çıktı; hiçbiri doğrulanmadıysa ilk kısmi çıktı.
    """
    if py_version:
        parts = py_version.split(".")
        try:
            major, minor = int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            major, minor = 0, 0
        if (major, minor) >= (3, 10):
            return None  # bu araclar 3.10+ decompile edemez
    first_partial: Optional[tuple[str, str, list[str], bool]] = None
    for mod_name in _PYLIB_MODULES:
        root = _pylib_search_root(mod_name)
        if root is None:
            continue
        if getattr(sys, "frozen", False) or not sys.executable:
            break   # donmuş uygulama: yorumlayıcı yok, süreç içine geri dönülmez
        # -I: kullanıcı site'ı, PYTHON* ortamı ve cwd sys.path'e girmez; kütüphane kökü
        # argümanla eklenir (kullanıcı site'ına kurulmuşsa da bulunur).
        run = _run_capped(
            [sys.executable, "-I", "-c", _PYLIB_CHILD_SCRIPT,
             str(pyc_path), mod_name, root, str(_CHILD_MAX_MEMORY_BYTES)],
            timeout=timeout,
        )
        if run.status not in ("ok", "truncated") or (run.status == "ok" and run.returncode != 0):
            logger.debug("%s alt sureci basarisiz (%s): durum=%s rc=%s",
                         mod_name, pyc_path.name, run.status, run.returncode)
            continue
        src, decode_problem = _decode_tool_output(run.stdout)
        if not src.strip():
            continue
        problems = _source_problems(src, tool=mod_name)
        truncated = run.status == "truncated"
        if truncated:
            problems.insert(0, _truncated_problem(mod_name))
        if decode_problem:
            problems.append(decode_problem)
        if not problems:
            return src, mod_name, [], False
        logger.debug("%s ciktisi kismi (%s): %s", mod_name, pyc_path.name, "; ".join(problems))
        if first_partial is None:
            first_partial = (src, mod_name, problems, truncated)
    return first_partial


# ---------------------------------------------------------------------------
# Sınırlı alt süreç: pycdc/pycdas + stdlib dis yedeği (AYRI SÜREÇTE)
# ---------------------------------------------------------------------------
# Güvenilmeyen .pyc'yi işleyen her alt süreç aynı kalıptan geçer (``_run_capped``):
# zaman aşımı, bellek bekçisi ve çıktı tavanı ebeveynde uygulanır. Çıktı ebeveyn
# belleğinde toplanmaz; geçici dosyaya yazılır, bekçi dosya boyutuna da bakar ve tavan
# aşılınca süreci öldürür (disk de sınırlı), okunan kısım tavanla sınırlıdır. Eskiden
# pycdc/pycdas çıktısı safe_run(capture_output=True) ile sınırsız toplanıyordu.
#
# stdlib dis yedeği .pyc gövdesini marshal.loads ile açmak zorunda. CPython belgesi
# marshal için "hatalı ya da kötü niyetle kurulmuş veriye karşı güvenli değildir" der;
# eskiden bu çağrı analiz sürecinin İÇİNDEYDİ. Artık ayrı bir yorumlayıcı (-s -S -P,
# safe_env) çalıştırılır, ana süreç gövdeyi hiç unmarshal etmez. Kod ÇALIŞTIRILMAZ.
#
# Sınırlar 2026-09-25 ölçümlerine dayanır (yerel 3.12 stdlib, 776 .pyc): dis en büyük
# çıktı 0,79 MB, en uzun 0,03 sn, tüm korpus tek süreçte 50 MB RSS; vendor pycdc/pycdas
# (b428976) en büyük stdout 83 KB / 1,53 MB (pycdas, tkinter/__init__: .pyc'nin 10
# katı), en büyük RSS 2,9 MB, en uzun 0,18 sn.
_CHILD_TIMEOUT = 60.0                     # sn; çağıranın zaman aşımı daha kısaysa o geçerli
_CHILD_MAX_MEMORY_BYTES = 1024 ** 3       # alt süreç bellek tavanı (1 GiB)
_CHILD_MAX_OUTPUT_BYTES = 64 * 1024 ** 2  # stdout tavanı; aşılırsa kesilir ve işaretlenir
_CHILD_MAX_STDERR_BYTES = 1024 ** 2       # okunan stderr (yalnız ilk satır + satır sayısı)
_CHILD_POLL_INTERVAL = 0.05               # sn; bekçinin örnekleme aralığı

# Alt süreç çıkış kodları (0 = tam çıktı).
_DIS_RC_NOT_CODE = 3
_DIS_RC_TRUNCATED = 4
_DIS_TRUNCATED_MARKER = "# KARADUL: disassembly çıktı sınırında kesildi"

# Alt süreçte çalışan betik (güvenilir kod, güvenilmeyen veri). Linux'ta bellek tavanı
# RLIMIT_AS ile çocukta konur; macOS'ta setrlimit(RLIMIT_AS/RLIMIT_DATA) EINVAL döner
# (bu makinede ölçüldü), orada ebeveyndeki bekçi (_process_memory_bytes) uygular.
# Çıktı tekrarlanabilir: sabit hash tohumu (frozenset sırası) + iç içe code
# nesnelerinin bellek adresleri (" at 0x...") silinir.
_DIS_CHILD_SCRIPT = f"""
import re, sys
path, max_out, max_mem = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
try:
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (max_mem, max_mem))
except Exception:
    pass
import dis, marshal, types
with open(path, "rb") as fh:
    data = fh.read()
code = marshal.loads(data[{_PYC_HEADER_SIZE_37}:])
if not isinstance(code, types.CodeType):
    sys.exit({_DIS_RC_NOT_CODE})
out = sys.stdout.buffer

_addr = re.compile(r" at 0x[0-9a-fA-F]+")

class _Capped:
    n = 0
    def write(self, s):
        b = _addr.sub("", s).encode("utf-8", "backslashreplace")
        if self.n + len(b) > max_out:
            raise OverflowError
        self.n += len(b)
        out.write(b)
        return len(s)
    def flush(self):
        pass

try:
    dis.dis(code, file=_Capped())
except OverflowError:
    out.write(("\\n" + {_DIS_TRUNCATED_MARKER!r} + "\\n").encode("utf-8"))
    out.flush()
    sys.exit({_DIS_RC_TRUNCATED})
out.flush()
"""


@functools.lru_cache(maxsize=1)
def _libproc_rusage():
    """macOS ``proc_pid_rusage`` + ``rusage_info_v0`` yapısı (yoksa None)."""
    import ctypes

    class _RusageInfoV0(ctypes.Structure):
        _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
            (name, ctypes.c_uint64) for name in (
                "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups",
                "ri_interrupt_wkups", "ri_pageins", "ri_wired_size",
                "ri_resident_size", "ri_phys_footprint",
                "ri_proc_start_abstime", "ri_proc_exit_abstime",
            )
        ]

    try:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        fn = lib.proc_pid_rusage
    except (OSError, AttributeError):
        return None
    fn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    fn.restype = ctypes.c_int
    return fn, _RusageInfoV0


def _process_memory_bytes(pid: int) -> Optional[int]:
    """Çalışan alt sürecin fiziksel bellek kullanımı (bayt); ölçülemiyorsa None.

    macOS: proc_pid_rusage (resident ile phys_footprint'in büyüğü); Linux:
    /proc/<pid>/status VmRSS. Başka platformda yalnız zaman aşımı korur.
    """
    if sys.platform == "darwin":
        api = _libproc_rusage()
        if api is None:
            return None
        fn, info_cls = api
        import ctypes
        info = info_cls()
        if fn(pid, 0, ctypes.byref(info)) != 0:  # 0 = RUSAGE_INFO_V0
            return None
        return int(max(info.ri_resident_size, info.ri_phys_footprint))
    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{pid}/status", "rb") as fh:
                for line in fh:
                    if line.startswith(b"VmRSS:"):
                        return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None
    return None


@dataclass
class _ChildRun:
    """Sınırlı alt süreç sonucu (``_run_capped``)."""

    returncode: Optional[int]      # None: bekçi öldürdü ya da süreç başlatılamadı
    stdout: bytes = b""            # en fazla tavan kadar; "truncated"da son satır sonuna kırpılmış
    stderr: bytes = b""            # en fazla _CHILD_MAX_STDERR_BYTES
    status: str = "ok"             # ok | truncated | timeout | memory | spawn:<Hata>


def _run_capped(
    cmd: Sequence[str],
    *,
    timeout: float,
    max_output: Optional[int] = None,
    env: Optional[dict[str, str]] = None,
) -> _ChildRun:
    """Alt süreci zaman aşımı + bellek bekçisi + çıktı tavanıyla çalıştır.

    stdout/stderr geçici dosyalara yazılır. Bekçi her ``_CHILD_POLL_INTERVAL``'da
    süreyi (``min(timeout, _CHILD_TIMEOUT)``), belleği (``_process_memory_bytes``)
    ve dosya boyutlarını (stdout > ``max_output``, stderr > ``_CHILD_MAX_OUTPUT_BYTES``)
    denetler; aşımda süreci öldürür. ``timeout``/``memory``: çıktı dönmez (yarım ve
    güvenilmez). ``truncated``: tavanda kesilmiş çıktı döner (son tam satıra kadar).
    ``env`` verilmezse ``safe_env()``.
    """
    limit = _CHILD_MAX_OUTPUT_BYTES if max_output is None else max_output
    deadline = time.monotonic() + min(timeout, _CHILD_TIMEOUT)
    with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
        try:
            proc = subprocess.Popen(
                [str(c) for c in cmd], stdin=subprocess.DEVNULL, stdout=out_f, stderr=err_f,
                env=safe_env() if env is None else env, close_fds=True, shell=False,
            )
        except OSError as exc:
            return _ChildRun(None, status=f"spawn:{type(exc).__name__}")
        status = "ok"
        try:
            while True:
                try:
                    proc.wait(timeout=_CHILD_POLL_INTERVAL)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() > deadline:
                    status = "timeout"
                    break
                if (os.fstat(out_f.fileno()).st_size > limit
                        or os.fstat(err_f.fileno()).st_size > _CHILD_MAX_OUTPUT_BYTES):
                    status = "truncated"
                    break
                used = _process_memory_bytes(proc.pid)
                if used is not None and used > _CHILD_MAX_MEMORY_BYTES:
                    status = "memory"
                    break
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        if status in ("timeout", "memory"):
            return _ChildRun(None, status=status)
        out_f.seek(0)
        stdout = out_f.read(limit + 1)
        err_f.seek(0)
        stderr = err_f.read(_CHILD_MAX_STDERR_BYTES)
    returncode: Optional[int] = None if status == "truncated" else proc.returncode
    if len(stdout) > limit:
        status = "truncated"
    if status == "truncated":
        stdout = stdout[:limit]
        cut = stdout.rfind(b"\n")
        if cut >= 0:
            stdout = stdout[:cut + 1]      # yarım satır / yarım UTF-8 dizisi kalmasın
    return _ChildRun(returncode, stdout, stderr, status)


def _run_tool(cmd: Sequence[str], *, timeout: float) -> _ChildRun:
    """Harici araç (pycdc/pycdas) çağrısı: ``_run_capped`` + ``safe_env``.

    Testlerin sahtelediği tek nokta; stdlib dis yedeği bunu KULLANMAZ (doğrudan
    ``_run_capped``), böylece araç sahtesi dis yedeğini etkilemez.
    """
    return _run_capped(cmd, timeout=timeout)


def _stdlib_dis_isolated(pyc_path: Path, *, timeout: float) -> tuple[Optional[str], str]:
    """``dis.dis(marshal.loads(...))``'i ayrı yorumlayıcıda çalıştır: (metin | None, durum).

    Çıktı çalıştırmadan çalıştırmaya aynıdır (sabit hash tohumu, adressiz code repr).
    Çıktı tavanını çocuk kendisi uygular (işaret satırı + rc=4); ebeveyn bekçisi
    ``_run_capped`` aynı tavanın biraz üstünde yedek olarak durur.

    Durum: ``ok`` | ``truncated`` (çıktı tavanında kesildi, sonunda işaret satırı var)
    | ``not_code`` | ``timeout`` | ``memory`` | ``rc=N`` | ``no_interpreter`` | ``spawn:<hata>``.
    """
    if getattr(sys, "frozen", False) or not sys.executable:
        # Donmuş uygulamada sys.executable bir yorumlayıcı değildir; süreç içi
        # marshal.loads'a geri dönülmez.
        return None, "no_interpreter"
    # -s -S -P: kullanıcı site-packages'ı, site ve cwd sys.path'e girmez. -I (-E) yerine
    # bu üçü: safe_env zaten PYTHON* taşımaz, PYTHONHASHSEED'in okunması gerekir.
    cmd = [
        sys.executable, "-s", "-S", "-P", "-c", _DIS_CHILD_SCRIPT,
        str(pyc_path), str(_CHILD_MAX_OUTPUT_BYTES), str(_CHILD_MAX_MEMORY_BYTES),
    ]
    run = _run_capped(
        cmd, timeout=timeout, max_output=_CHILD_MAX_OUTPUT_BYTES + 4096,
        env=safe_env({"PYTHONHASHSEED": "0"}),
    )
    if run.status == "truncated":
        # Çocuğun kendi sınırı devre dışıysa ebeveyn kesti: yine işaretli teslim.
        text, _ = _decode_tool_output(run.stdout)
        return text + "\n" + _DIS_TRUNCATED_MARKER + "\n", "truncated"
    if run.status != "ok":
        return None, run.status
    rc = run.returncode
    if rc == _DIS_RC_NOT_CODE:
        return None, "not_code"
    if rc not in (0, _DIS_RC_TRUNCATED):
        return None, f"rc={rc}"
    text, _ = _decode_tool_output(run.stdout)
    if not text.strip():
        return None, "empty"
    return text, "truncated" if rc == _DIS_RC_TRUNCATED else "ok"


def _disassemble(
    pyc_path: Path,
    py_version: Optional[str],
    *,
    timeout: float,
    extra_paths: Optional[Sequence[str]] = None,
) -> Optional[tuple[str, str, bool]]:
    """Son care: bytecode disassembly. (metin, yontem, kesildi_mi) dondur veya None.

    Kesilen metin (alt süreç çıktı tavanı) sonunda ``_DIS_TRUNCATED_MARKER`` taşır.

    1. pycdas (Decompyle++ disassembler) -- versiyon-bagimsiz, tercih edilir.
       ``extra_paths`` pycdc ile AYNI olmalı: setup_pycdc.sh ikisini de
       vendor/pycdc'ye kurar; verilmezse pycdas hiç bulunmaz ve farklı sürümlü
       .pyc'ler (stdlib dis kullanılamaz) "none"a düşer.
    2. stdlib ``dis`` -- yalniz .pyc surumu CALISAN Python ile uyumluysa
       (marshal biçimi sürüme bağlı). AYRI SÜREÇTE çalışır (bkz.
       ``_stdlib_dis_isolated``). pycdas kuruluyken meşru .pyc'de bu yedeğe
       düşülmüyor (ölçüm: 995/995 .pyc'de pycdas yetti); yedeğe düşüren, pycdas'ın
       dökemediği içeriktir -- yani tam da güvenilmeyen veri.
    """
    # 1. pycdas
    pycdas = resolve_tool("pycdas", extra_paths=extra_paths)
    if pycdas is not None:
        run = _run_tool([pycdas, str(pyc_path)], timeout=timeout)
        text, _ = _decode_tool_output(run.stdout)
        # pycdas tanımadığı magic'te de rc=0 döner ("Bad MAGIC!" stderr'de,
        # stdout: "<ad> (Python -1.-1)" + "<NULL>"). En az bir kod nesnesi
        # dökümü ("[Code]") yoksa disassembly sayılmaz.
        has_code = any(ln.strip() == "[Code]" for ln in text.splitlines())
        if run.status == "truncated" and has_code:
            logger.warning(
                "pycdas ciktisi %d bayt sinirinda kesildi: %s",
                _CHILD_MAX_OUTPUT_BYTES, pyc_path.name,
            )
            return text + _DIS_TRUNCATED_MARKER + "\n", "disasm", True
        if run.status == "ok" and run.returncode == 0 and has_code:
            return text, "disasm", False
        logger.debug(
            "pycdas kod nesnesi dokemedi (%s): durum=%s rc=%s",
            pyc_path.name, run.status, run.returncode,
        )

    # 2. stdlib dis (yalniz .pyc surumu CALISAN Python ile ayni major.minor ise),
    #    ayrı süreçte. Ana süreç yalnız 4 baytlık magic'e bakar.
    running = f"{sys.version_info.major}.{sys.version_info.minor}"
    if py_version:
        pv_parts = py_version.split(".")
        pv_mm = ".".join(pv_parts[:2]) if len(pv_parts) >= 2 else py_version
        if pv_mm != running:
            return None  # surum uyusmuyor -> marshal bicimi farkli
    try:
        with open(pyc_path, "rb") as fh:
            head = fh.read(4)
    except OSError as exc:
        logger.debug("stdlib dis: .pyc okunamadi (%s): %s", pyc_path.name, exc)
        return None
    if not has_valid_pyc_header(head):
        return None
    dis_text, status = _stdlib_dis_isolated(pyc_path, timeout=timeout)
    if dis_text is None:
        logger.debug("stdlib dis (alt surec) basarisiz (%s): %s", pyc_path.name, status)
        return None
    if status == "truncated":
        logger.warning(
            "stdlib dis ciktisi %d bayt sinirinda kesildi: %s",
            _CHILD_MAX_OUTPUT_BYTES, pyc_path.name,
        )
    return dis_text, "disasm", status == "truncated"


def pycdc_available(extra_paths: Optional[Sequence[str]] = None) -> bool:
    """pycdc çözümlenebiliyor mu (rapor notu için; "pycdc kurun" önerisi yalnız yoksa)."""
    return resolve_tool("pycdc", extra_paths=extra_paths) is not None


def decompile_pyc(
    pyc_path: Path,
    out_dir: Path,
    *,
    py_version: Optional[str] = None,
    timeout: float = 120.0,
    extra_paths: Optional[Sequence[str]] = None,
    out_stem: Optional[str] = None,
) -> DecompileResult:
    """Tek bir (header'i gecerli) .pyc'yi decompile et.

    pyc_path'in header'i onarilmis olmali (bkz. repair_pyc_header). py_version
    verilmezse header'daki magic'ten okunur. ``out_stem`` çıktı dosya adı kökü
    (verilmezse ``pyc_path.stem``; onarılmış ``x.fixed.pyc`` için çağıran "x" verir).

    Katmanli: pycdc -> decompyle3/uncompyle6 -> disassembly -> none. pycdc çıktısı
    doğrulanamazsa ``<kök>.partial.py`` olarak saklanır ve zincir devam eder.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    result = DecompileResult(source_path=pyc_path)

    body = pyc_path.read_bytes()
    if py_version is None:
        py_version = version_from_pyc_bytes(body)

    stem = out_stem or pyc_path.stem
    py_out = out_dir / f"{stem}.py"

    # 1. pycdc -- yalnız doğrulanmış çıktı kaynak sayılır (bkz. _source_problems)
    # (kaynak, sorunlar, araç, çıktı tavanında kesildi mi)
    partial: Optional[tuple[str, list[str], str, bool]] = None
    partial_tool = ""
    pycdc_out = _decompile_with_pycdc(pyc_path, timeout=timeout, extra_paths=extra_paths)
    if pycdc_out is not None:
        src, problems, cut = pycdc_out
        if not problems:
            py_out.write_text(src, encoding="utf-8", errors="replace")
            result.success = True
            result.method = "pycdc"
            result.output_path = py_out
            return result
        partial = (src, problems, "pycdc", cut)
        logger.debug("pycdc ciktisi kismi (%s): %s", pyc_path.name, "; ".join(problems))

    # 2. decompyle3 / uncompyle6 (opsiyonel, < 3.10) -- ayrı süreçte, aynı doğrulama
    pylib = _decompile_with_pylib(pyc_path, py_version, timeout=timeout)
    if pylib is not None:
        src, method, problems, cut = pylib
        if not problems:
            py_out.write_text(src, encoding="utf-8", errors="replace")
            result.success = True
            result.method = method
            result.output_path = py_out
            return result
        if partial is None:
            partial = (src, problems, method, cut)

    # Doğrulanamayan çıktı atılmaz: okunabilir parçalar (imzalar, sabitler) taşır.
    # .partial.py + uyarı başlığı; sayımda "decompiled" DEĞİL.
    if partial is not None:
        src, problems, tool, cut = partial
        reason = "; ".join(problems)
        partial_out = out_dir / f"{stem}.partial.py"
        partial_out.write_text(
            _partial_banner(reason, tool) + src
            + (f"\n# KARADUL: {_truncated_problem(tool)}\n" if cut else ""),
            encoding="utf-8", errors="replace",
        )
        result.partial_path = partial_out
        result.partial_reason = reason
        result.truncated = cut
        partial_tool = tool

    # 3. disassembly fallback
    disasm = _disassemble(pyc_path, py_version, timeout=timeout, extra_paths=extra_paths)
    if disasm is not None:
        text, method, cut_disasm = disasm
        result.truncated = result.truncated or cut_disasm
        disasm_out = out_dir / f"{stem}.disasm.txt"
        disasm_out.write_text(text, encoding="utf-8", errors="replace")
        result.success = False       # kaynak degil; kismi kurtarma
        result.method = method
        result.output_path = disasm_out
        result.is_disassembly = True
        return result

    # 4. yalnız kısmi decompiler çıktısı ya da hiçbiri
    if result.partial_path is not None:
        result.method = f"{partial_tool}_partial"
        result.output_path = result.partial_path
        result.error = f"disassembly yok; yalniz kismi {partial_tool} ciktisi"
        return result
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
