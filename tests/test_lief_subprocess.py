"""lief subprocess izolasyon testleri (v1.12 teknik borc).

Bu testler `karadul.utils.lief_subprocess.parse_in_subprocess` ve
`parse_bytes_in_subprocess` fonksiyonlarinin guvenli sekilde calistigini
dogrular:
- Happy path: gercek bir Mach-O fixture lief ile parse edilir,
  cocuk process exit 0 ve dogru dict doner.
- Hata yollari: dosya yok, bos veri, cok buyuk dosya, gecersiz binary,
  cocuk process timeout, cocuk process sinyalle olur (SIGSEGV simulasyonu).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

from karadul.utils import lief_subprocess
from karadul.utils.lief_subprocess import (
    parse_bytes_in_subprocess,
    parse_in_subprocess,
)

FIXTURE_MACHO = Path(__file__).parent / "fixtures" / "sample_macho"


def _lief_available() -> bool:
    try:
        import lief  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _lief_available(), reason="lief kurulu degil")
@pytest.mark.skipif(not FIXTURE_MACHO.exists(), reason="sample_macho fixture yok")
def test_parse_in_subprocess_happy_path_macho():
    """Gercek Mach-O fixture subprocess'te parse edilebilmeli."""
    result = parse_in_subprocess(FIXTURE_MACHO, timeout=30)
    assert result is not None, "Gecerli Mach-O parse edilemedi"
    assert isinstance(result, dict)
    assert result.get("path") == str(FIXTURE_MACHO)
    # Mach-O format imzasi (lief versiyonuna gore "MACHO" ya da "MACH_O")
    fmt = (result.get("format") or "").upper()
    assert "MACH" in fmt, "Beklenen format MACH-O degil: %r" % fmt
    # En az bir segment veya section olmali
    assert (result.get("segments") or result.get("sections")), (
        "Mach-O parse'tan ne segment ne section dondu"
    )


def test_parse_in_subprocess_missing_file_returns_none(tmp_path: Path):
    """Var olmayan dosya icin None donmeli, exception firlamamali."""
    missing = tmp_path / "yok.bin"
    assert parse_in_subprocess(missing, timeout=5) is None


def test_parse_in_subprocess_oversize_returns_none(tmp_path: Path):
    """max_size_mb limitini asan dosya hic process baslatmamali."""
    big = tmp_path / "big.bin"
    big.write_bytes(b"\x00" * 1024)
    # 0 MB limit -> her dosya buyuk sayilir
    result = parse_in_subprocess(big, timeout=5, max_size_mb=0)
    assert result is None


def test_parse_in_subprocess_garbage_returns_none(tmp_path: Path):
    """Gecersiz/cop binary lief tarafindan parse edilemez, None donmeli."""
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"NOT_A_BINARY_FILE_JUST_RANDOM_BYTES" * 4)
    # lief None dondurur veya exception verir; her iki halde de None bekleriz
    result = parse_in_subprocess(junk, timeout=15)
    assert result is None


def test_parse_in_subprocess_signal_death_returns_none(tmp_path: Path):
    """Cocuk process sinyalle (negatif returncode) olunce None donmeli.

    `subprocess.run`'i mock'layip negatif returncode (SIGSEGV simulasyonu)
    dondururuz; helper bunu crash olarak yakalayip None donmeli.
    """
    fake_file = tmp_path / "fake.bin"
    fake_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)

    fake_completed = mock.Mock()
    fake_completed.returncode = -11  # SIGSEGV
    fake_completed.stdout = ""
    fake_completed.stderr = "Segmentation fault"

    with mock.patch.object(
        lief_subprocess.subprocess, "run", return_value=fake_completed
    ):
        result = parse_in_subprocess(fake_file, timeout=5)
    assert result is None


def test_parse_in_subprocess_timeout_returns_none(tmp_path: Path):
    """subprocess.TimeoutExpired sessizce yakalanip None donmeli."""
    fake_file = tmp_path / "slow.bin"
    fake_file.write_bytes(b"\x00" * 128)

    import subprocess as _sp

    def _raise_timeout(*args, **kwargs):
        raise _sp.TimeoutExpired(cmd="python", timeout=1)

    with mock.patch.object(lief_subprocess.subprocess, "run", side_effect=_raise_timeout):
        result = parse_in_subprocess(fake_file, timeout=1)
    assert result is None


def test_parse_bytes_in_subprocess_empty_returns_none():
    """Bos bytes giris None dondurmeli, tempfile yazmamali."""
    assert parse_bytes_in_subprocess(b"", timeout=5) is None


def test_parse_bytes_in_subprocess_oversize_returns_none():
    """max_size_mb=0 ile her bytes giris reddedilmeli."""
    assert parse_bytes_in_subprocess(b"x" * 1024, timeout=5, max_size_mb=0) is None


@pytest.mark.skipif(not _lief_available(), reason="lief kurulu degil")
@pytest.mark.skipif(not FIXTURE_MACHO.exists(), reason="sample_macho fixture yok")
def test_parse_bytes_in_subprocess_macho_roundtrip():
    """Bytes API gercek Mach-O datasi icin de calismali ve tempfile temizlenmeli."""
    data = FIXTURE_MACHO.read_bytes()
    before = set(os.listdir(os.path.dirname(os.path.abspath(__file__))))
    result = parse_bytes_in_subprocess(data, timeout=30)
    after = set(os.listdir(os.path.dirname(os.path.abspath(__file__))))
    assert before == after, "Bytes API tempfile sizdirdi"
    assert result is not None
    assert "MACH" in (result.get("format") or "").upper()
