"""packed_binary.py kapsamli unit testleri (v1.14.5).

Bu test paketi `karadul/analyzers/packed_binary.py` (1438 LOC) modulunu
sentetik byte yapilari ve mock subprocess cagrilari ile dogrular. Gercek
binary, gercek UPX/decompyle6 cagrisi yapilmaz.

Test gruplari:
    1. ``calculate_entropy``       -- numpy fast-path + Counter fallback parite
    2. ``calculate_section_entropy`` -- chunked entropy profili
    3. ``PackingDetector.detect``  -- 5 adim pipeline + early return
    4. ``_check_upx``              -- UPX magic tespit
    5. ``_check_pyinstaller``      -- MEI cookie offset + version dispatch
    6. ``_check_nuitka``           -- imza tarama (regex tek-pass)
    7. ``_analyze_section_entropies`` -- yuksek entropy section tespiti
    8. ``_count_imports``          -- lief subprocess fallback
    9. ``PyInstallerExtractor``    -- TOC parse, _extract_entry guard'lari
    10. ``BinaryUnpacker.unpack``  -- 3 yol dispatch (UPX/PyInst/Nuitka/Generic)
    11. ``analyze_packed_binary``  -- public API smoke
    12. GUVENLIK -- safe_zlib_decompress 100MB limit, zip bomb
    13. GUVENLIK -- path traversal (PyInstaller TOC name)
    14. GUVENLIK -- Windows reserved name guard (multi-component path)

mypy --strict uyumlu, pytest -x calistirilabilir.
"""

from __future__ import annotations

import os
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Any, Sequence

import pytest

from karadul.analyzers.packed_binary import (
    _MAX_PYINSTALLER_DECOMPRESS,
    _WINDOWS_RESERVED_NAMES,
    BinaryUnpacker,
    ExtractedFile,
    NUITKA_SIGNATURES,
    PYINSTALLER_COOKIE_SIZE_NEW,
    PYINSTALLER_MAGIC,
    PackingDetector,
    PackingInfo,
    PackingType,
    PyInstallerExtractor,
    SectionEntropy,
    UnpackResult,
    UPX_MAGIC,
    _is_windows_reserved,
    analyze_packed_binary,
    calculate_entropy,
    calculate_section_entropy,
)
from karadul.config import Config


# ---------------------------------------------------------------------------
# Yardimci kurucular -- sentetik data
# ---------------------------------------------------------------------------

def _make_pyinstaller_cookie(
    pkg_len: int = 0,
    toc_off: int = 0,
    toc_len: int = 0,
    py_ver: int = 39,
    cookie_size: int = PYINSTALLER_COOKIE_SIZE_NEW,
) -> bytes:
    """Sentetik PyInstaller cookie (88 byte yeni format).

    Cookie struct: magic(8) + pkg_len(I) + toc_off(I) + toc_len(I) + py_ver(I)
    + python_dll(64).
    """
    head = struct.pack("!8sIIII", PYINSTALLER_MAGIC, pkg_len, toc_off, toc_len, py_ver)
    pad = b"\x00" * (cookie_size - len(head))
    return head + pad


def _make_toc_entry(
    name: str,
    entry_off: int,
    data_len: int,
    uncomp_len: int,
    cflag: int = 0,
    tflag: int = ord("s"),
) -> bytes:
    """Sentetik TOC entry: 18 byte header + null-terminated name + padding.

    Header layout (kod ile parite):
        pos[0:4]    = entry_len (raw, includes self) "!I"
        pos[4:8]    = entry_off "!I"
        pos[8:12]   = data_len  "!I"
        pos[12:16]  = uncomp_len "!I"
        pos[16]     = cflag "!B"
        pos[17]     = tflag "!B"
        pos[18:..]  = name + null + padding (raw_entry_len'e kadar)
    """
    name_bytes = name.encode("utf-8") + b"\x00"
    # name'in en az 1 byte olmasi yeterli; biz hem header hem name'i hesaplariz
    entry_len = 18 + len(name_bytes)
    body = struct.pack(
        "!IIIIBB",
        entry_len,
        entry_off,
        data_len,
        uncomp_len,
        cflag,
        tflag,
    )
    return body + name_bytes


def _zlib_compress(data: bytes) -> bytes:
    """Standart zlib compress (wbits=15)."""
    return zlib.compress(data)


def _build_pyinstaller_blob(
    files: list[tuple[str, bytes, int]],
    *,
    compressed: bool = False,
) -> tuple[bytes, int]:
    """Sentetik PyInstaller binary olustur.

    Layout:
        [stub bytes]
        [package payload] -- pkg_start
            [data1][data2]...
            [TOC bytes]
        [cookie 88 byte] -- son 4096 byte icinde

    Args:
        files: (name, payload, type_flag) listesi.
        compressed: True ise payload'lari zlib ile sikistir.

    Returns:
        (binary blob, cookie_offset)
    """
    stub = b"\x7fELF" + b"\x00" * 1024  # Sahte ELF stub

    # Payload + TOC olustur
    payloads = bytearray()
    toc_entries: list[tuple[str, int, int, int, int]] = []
    # her entry: (name, offset_in_pkg, stored_len, original_len, tflag)
    cur_off = 0
    for name, payload, tflag in files:
        if compressed:
            stored = _zlib_compress(payload)
            cflag = 1
        else:
            stored = payload
            cflag = 0
        toc_entries.append((name, cur_off, len(stored), len(payload), tflag))
        # cflag'i ayri tasi
        toc_entries[-1] = (name, cur_off, len(stored), len(payload), tflag, cflag)  # type: ignore[assignment]
        payloads.extend(stored)
        cur_off += len(stored)

    # TOC bytes
    toc_bytes = bytearray()
    for name, off, dlen, ulen, tflag, cflag in toc_entries:  # type: ignore[misc]
        toc_bytes.extend(
            _make_toc_entry(name, off, dlen, ulen, cflag=cflag, tflag=tflag)
        )

    # Package = payloads + TOC
    package = bytes(payloads) + bytes(toc_bytes)
    pkg_len = len(package)
    toc_off_in_pkg = len(payloads)
    toc_len = len(toc_bytes)

    cookie = _make_pyinstaller_cookie(
        pkg_len=pkg_len,
        toc_off=toc_off_in_pkg,
        toc_len=toc_len,
        py_ver=39,
    )

    blob = stub + package + cookie
    cookie_offset = len(stub) + len(package)
    return blob, cookie_offset


def _make_random_high_entropy(size: int) -> bytes:
    """Yuksek entropy'li (>7.0) byte dizisi."""
    return os.urandom(size)


def _make_low_entropy(size: int, fill: int = 0x41) -> bytes:
    """Dusuk entropy'li (~0) byte dizisi (tek byte tekrar)."""
    return bytes([fill]) * size


# ---------------------------------------------------------------------------
# 1. calculate_entropy -- numpy fast path + Counter fallback parite
# ---------------------------------------------------------------------------

class TestCalculateEntropy:
    """Shannon entropy hesabi: hizli yol + fallback paritesi."""

    def test_empty_data_returns_zero(self) -> None:
        assert calculate_entropy(b"") == 0.0

    def test_single_byte_repeated_zero_entropy(self) -> None:
        # Tek bir byte tekrar -> entropy 0
        assert calculate_entropy(b"\x00" * 1024) == pytest.approx(0.0, abs=1e-9)

    def test_uniform_distribution_max_entropy(self) -> None:
        # 0..255 her byte ayni sayida -> entropy 8.0
        data = bytes(range(256)) * 16
        assert calculate_entropy(data) == pytest.approx(8.0, abs=1e-6)

    def test_two_byte_uniform_entropy_one(self) -> None:
        # Yari 'A', yari 'B' -> entropy 1.0
        data = b"A" * 512 + b"B" * 512
        assert calculate_entropy(data) == pytest.approx(1.0, abs=1e-6)

    def test_numpy_fastpath_matches_counter_fallback(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Once normal yolla (numpy varsa onu kullanir)
        data = os.urandom(8192)
        baseline = calculate_entropy(data)

        # numpy import'unu engelle -> Counter fallback'e dusmeli
        import builtins
        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "numpy":
                raise ImportError("numpy disabled for test")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        fallback = calculate_entropy(data)

        # Iki yol da ayni sonucu vermeli (fp tolerance icinde)
        assert fallback == pytest.approx(baseline, abs=1e-9)

    def test_random_data_high_entropy(self) -> None:
        data = os.urandom(16384)
        ent = calculate_entropy(data)
        # Random veri ~7.9-8.0 arasi olmali
        assert ent > 7.5


# ---------------------------------------------------------------------------
# 2. calculate_section_entropy
# ---------------------------------------------------------------------------

class TestCalculateSectionEntropy:
    """Chunk-bazli entropy profili."""

    def test_empty_data_returns_empty_list(self) -> None:
        assert calculate_section_entropy(b"") == []

    def test_short_chunk_below_min_size_skipped(self) -> None:
        # 256 byte'tan kucuk chunk yaniltici sayilir, atlanir
        assert calculate_section_entropy(b"A" * 100, section_size=65536) == []

    def test_uniform_chunks_zero_entropy(self) -> None:
        # 64KB uniform -> entropy 0
        ents = calculate_section_entropy(b"A" * 65536)
        assert len(ents) == 1
        assert ents[0] == pytest.approx(0.0, abs=1e-9)

    def test_mixed_chunks_returns_per_section(self) -> None:
        # Iki chunk: bir uniform, bir random
        data = b"A" * 65536 + os.urandom(65536)
        ents = calculate_section_entropy(data, section_size=65536)
        assert len(ents) == 2
        assert ents[0] < 0.1
        assert ents[1] > 7.0

    def test_custom_section_size(self) -> None:
        # 1KB chunk'lar
        data = b"A" * 4096
        ents = calculate_section_entropy(data, section_size=1024)
        assert len(ents) == 4
        assert all(e == pytest.approx(0.0, abs=1e-9) for e in ents)


# ---------------------------------------------------------------------------
# 3. PackingDetector.detect -- 5 adim pipeline
# ---------------------------------------------------------------------------

class TestPackingDetectorDetect:
    """detect() pipeline ordering, file guard, OOM koruma."""

    def test_missing_file_returns_not_packed(self, tmp_path: Path, config: Config) -> None:
        det = PackingDetector(config)
        info = det.detect(tmp_path / "yok.bin")
        assert info.is_packed is False
        assert info.packing_type == PackingType.NONE
        assert any("Dosya bulunamadi" in e for e in info.evidence)

    def test_oversize_file_rejected(
        self, tmp_path: Path, config: Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # max_binary_size_bytes'i kucuk ayarla
        monkeypatch.setattr(config.security, "max_binary_size_bytes", 1024)
        big = tmp_path / "big.bin"
        big.write_bytes(b"\x00" * 4096)
        det = PackingDetector(config)
        info = det.detect(big)
        assert info.is_packed is False
        assert any("cok buyuk" in e for e in info.evidence)

    def test_upx_short_circuits_pipeline(self, tmp_path: Path, config: Config) -> None:
        # UPX magic varsa diger kontroller atlanir
        data = b"\x00" * 256 + UPX_MAGIC + b"\x00" * 256
        bin_path = tmp_path / "upx.bin"
        bin_path.write_bytes(data)
        det = PackingDetector(config)
        info = det.detect(bin_path)
        assert info.is_packed is True
        assert info.packing_type == PackingType.UPX
        assert info.confidence == pytest.approx(0.95)
        assert info.metadata["upx_offset"] == 256

    def test_pyinstaller_detection(self, tmp_path: Path, config: Config) -> None:
        # PyInstaller MEI magic
        cookie = _make_pyinstaller_cookie(pkg_len=128, toc_off=0, toc_len=64)
        data = b"\x00" * 1024 + cookie
        bin_path = tmp_path / "pyinst.bin"
        bin_path.write_bytes(data)
        det = PackingDetector(config)
        info = det.detect(bin_path)
        assert info.is_packed is True
        assert info.packing_type == PackingType.PYINSTALLER

    def test_nuitka_detection(self, tmp_path: Path, config: Config) -> None:
        data = b"\x00" * 1024 + b"__nuitka_module_data" + b"\x00" * 1024
        bin_path = tmp_path / "nuitka.bin"
        bin_path.write_bytes(data)
        det = PackingDetector(config)
        info = det.detect(bin_path)
        assert info.is_packed is True
        assert info.packing_type == PackingType.NUITKA
        assert info.confidence == pytest.approx(0.85)

    def test_low_entropy_no_indicator_returns_not_packed(
        self, tmp_path: Path, config: Config,
    ) -> None:
        # Tum dusuk entropy + magic yok -> packed degil
        bin_path = tmp_path / "plain.bin"
        bin_path.write_bytes(b"A" * 65536)
        det = PackingDetector(config)
        info = det.detect(bin_path)
        assert info.is_packed is False
        assert info.packing_type == PackingType.NONE

    def test_high_entropy_unknown_packed(
        self, tmp_path: Path, config: Config,
    ) -> None:
        # Magic yok + tamamen random -> UNKNOWN_PACKED
        bin_path = tmp_path / "rand.bin"
        bin_path.write_bytes(_make_random_high_entropy(65536 * 4))
        det = PackingDetector(config)
        info = det.detect(bin_path)
        # En azindan packed olarak isaretlemeli
        assert info.is_packed is True
        assert info.packing_type in (
            PackingType.UNKNOWN_PACKED, PackingType.GENERIC_PACKED,
        )


# ---------------------------------------------------------------------------
# 4. _check_upx
# ---------------------------------------------------------------------------

class TestCheckUpx:
    def test_upx_magic_found(self) -> None:
        data = b"AAAA" + UPX_MAGIC + b"BBBB"
        assert PackingDetector._check_upx(data) == 4

    def test_upx_magic_at_start(self) -> None:
        assert PackingDetector._check_upx(UPX_MAGIC + b"rest") == 0

    def test_no_upx_returns_none(self) -> None:
        assert PackingDetector._check_upx(b"plain ELF data no magic") is None

    def test_upx_magic_in_random_data(self) -> None:
        # Magic 4 byte oldugu icin random'da rastlama riski cok dusuk
        data = b"\x00" * 4096
        assert PackingDetector._check_upx(data) is None


# ---------------------------------------------------------------------------
# 5. _check_pyinstaller -- cookie offset, version dispatch
# ---------------------------------------------------------------------------

class TestCheckPyInstaller:
    def test_no_magic_returns_none(self) -> None:
        assert PackingDetector._check_pyinstaller(b"\x00" * 8192) is None

    def test_magic_in_last_4kb(self) -> None:
        cookie = _make_pyinstaller_cookie(pkg_len=10, toc_off=0, toc_len=4)
        data = b"\x00" * 1024 + cookie
        result = PackingDetector._check_pyinstaller(data)
        assert result is not None
        assert result["magic_found"] is True
        # Cookie offset = 1024
        assert result["cookie_offset"] == 1024
        assert result["package_length"] == 10
        assert result["cookie_format"] == "new"

    def test_magic_outside_last_4kb_full_scan(self) -> None:
        # Magic sadece dosyanin basinda -> tam tarama
        cookie = _make_pyinstaller_cookie(pkg_len=42)
        # En az 4096 + 88 = ~4184 byte tampon ekleyip, magic'i en basa koy
        data = cookie + b"\x00" * 8192
        result = PackingDetector._check_pyinstaller(data)
        assert result is not None
        assert result["cookie_offset"] == 0

    def test_old_cookie_size_dispatch(self) -> None:
        # Eski 64-byte cookie format
        cookie = _make_pyinstaller_cookie(pkg_len=5, cookie_size=64)
        # Cookie son 64 byte'a yerlesecek; sonra ekstra byte yok
        data = b"\x00" * 100 + cookie
        result = PackingDetector._check_pyinstaller(data)
        assert result is not None
        # Yeni format icin yeterince yer olmadigi icin "old" veya en azindan parse olmali
        assert result["cookie_format"] in ("old", "new")

    def test_truncated_cookie_parse_error(self) -> None:
        # Magic var ama cookie yarim
        data = b"\x00" * 100 + PYINSTALLER_MAGIC + b"\x01\x02"  # 10 byte yetersiz
        result = PackingDetector._check_pyinstaller(data)
        assert result is not None
        # Parse hatasi durumunda yine dict gelir
        assert result["magic_found"] is True


# ---------------------------------------------------------------------------
# 6. _check_nuitka
# ---------------------------------------------------------------------------

class TestCheckNuitka:
    def test_no_signatures_returns_none(self) -> None:
        assert PackingDetector._check_nuitka(b"plain ELF data") is None

    def test_single_signature_found(self) -> None:
        data = b"\x00" * 100 + b"__nuitka_module_init" + b"\x00" * 100
        result = PackingDetector._check_nuitka(data)
        assert result is not None
        assert any("Nuitka" in s for s in result)
        assert any("__nuitka_" in s for s in result)

    def test_multiple_signatures_found(self) -> None:
        data = (
            b"prefix"
            + b"__nuitka_"
            + b"middle"
            + b"Nuitka-Scons"
            + b"suffix"
            + b"NUITKA_PACKAGE_"
            + b"end"
        )
        result = PackingDetector._check_nuitka(data)
        assert result is not None
        assert len(result) >= 3

    def test_signature_count_matches_unique_only(self) -> None:
        # Ayni imza 3 kez -> tek satir doner
        data = b"__nuitka_" * 3
        result = PackingDetector._check_nuitka(data)
        assert result is not None
        assert sum(1 for s in result if "__nuitka_" in s) == 1


# ---------------------------------------------------------------------------
# 7. _analyze_section_entropies
# ---------------------------------------------------------------------------

class TestAnalyzeSectionEntropies:
    def test_uniform_data_no_packed_sections(self, config: Config) -> None:
        det = PackingDetector(config)
        sections = det._analyze_section_entropies(b"A" * 65536 * 2, "test.bin")
        # lief muhtemelen parse edemez (pure byte) -> fallback 64KB blok
        assert len(sections) >= 1
        assert all(not s.is_packed for s in sections)

    def test_random_data_packed_sections(self, config: Config) -> None:
        det = PackingDetector(config)
        sections = det._analyze_section_entropies(
            _make_random_high_entropy(65536 * 2), "rand.bin",
        )
        assert len(sections) >= 1
        # Random veri yuksek entropi olmali
        assert any(s.is_packed for s in sections)

    def test_short_data_skipped(self, config: Config) -> None:
        # 256'dan kucuk veri -> hicbir section
        det = PackingDetector(config)
        sections = det._analyze_section_entropies(b"A" * 100, "tiny.bin")
        assert sections == []


# ---------------------------------------------------------------------------
# 8. _count_imports
# ---------------------------------------------------------------------------

class TestCountImports:
    def test_returns_int_or_none(self) -> None:
        # Sentetik byte; lief subprocess basariyla calismayabilir
        result = PackingDetector._count_imports(b"\x00" * 1024)
        assert result is None or isinstance(result, int)

    def test_lief_subprocess_import_error_returns_none(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # lief_subprocess import edilemezse None
        import builtins
        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if "lief_subprocess" in name:
                raise ImportError("blocked")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert PackingDetector._count_imports(b"\x00" * 100) is None


# ---------------------------------------------------------------------------
# 9. PyInstallerExtractor.extract + _parse_cookie + _parse_toc
# ---------------------------------------------------------------------------

class TestPyInstallerExtractor:
    def test_parse_cookie_basic(self) -> None:
        cookie = _make_pyinstaller_cookie(
            pkg_len=100, toc_off=50, toc_len=10, py_ver=39,
        )
        info = PyInstallerExtractor._parse_cookie(cookie, 0)
        assert info["package_length"] == 100
        assert info["toc_offset"] == 50
        assert info["toc_length"] == 10
        assert info["python_version"] == 39
        assert info["magic"] == PYINSTALLER_MAGIC

    def test_parse_toc_single_entry(self) -> None:
        # v1.14.5 fix: _parse_toc struct.unpack format/degisken sayisi uyumsuzlugu
        # giderildi (packed_binary.py:828-831). 5 deger -> 5 degisken.
        entry = _make_toc_entry(
            "myscript.py", entry_off=0, data_len=5, uncomp_len=5, tflag=ord("s"),
        )
        data = entry
        entries = PyInstallerExtractor._parse_toc(data, 0, len(entry))
        assert len(entries) == 1
        assert entries[0]["name"] == "myscript.py"

    def test_parse_toc_multiple_entries(self) -> None:
        e1 = _make_toc_entry("a.py", 0, 10, 10, tflag=ord("s"))
        e2 = _make_toc_entry("b.so", 10, 20, 20, tflag=ord("b"))
        toc = e1 + e2
        entries = PyInstallerExtractor._parse_toc(toc, 0, len(toc))
        assert len(entries) == 2

    def test_parse_toc_handles_short_data_gracefully(self) -> None:
        # 18 byte'tan kucuk -> hicbir entry
        entries = PyInstallerExtractor._parse_toc(b"\x00" * 10, 0, 10)
        assert entries == []

    def test_parse_toc_empty_region(self) -> None:
        # toc_length=0 -> dongu girmez
        entries = PyInstallerExtractor._parse_toc(b"\x00" * 100, 0, 0)
        assert entries == []

    def test_extract_missing_file(self, tmp_path: Path, config: Config) -> None:
        ext = PyInstallerExtractor(config)
        result = ext.extract(tmp_path / "yok.bin", tmp_path / "out")
        assert result.success is False
        assert any("okunamadi" in e for e in result.errors)

    def test_extract_no_cookie(self, tmp_path: Path, config: Config) -> None:
        # Magic yok
        bin_path = tmp_path / "nocookie.bin"
        bin_path.write_bytes(b"\x00" * 4096)
        ext = PyInstallerExtractor(config)
        result = ext.extract(bin_path, tmp_path / "out")
        assert result.success is False
        assert any("cookie bulunamadi" in e for e in result.errors)

    def test_extract_full_pipeline_uncompressed(
        self, tmp_path: Path, config: Config,
    ) -> None:
        files: list[tuple[str, bytes, int]] = [
            ("hello.pyc", b"PYC_HEADER" + b"\x00" * 50, ord("s")),
            ("data.bin", b"DATA_PAYLOAD" * 8, ord("d")),
        ]
        blob, _ = _build_pyinstaller_blob(files, compressed=False)
        bin_path = tmp_path / "pyinst.bin"
        bin_path.write_bytes(blob)
        out = tmp_path / "out"
        ext = PyInstallerExtractor(config)
        result = ext.extract(bin_path, out)
        assert isinstance(result, UnpackResult)
        assert result.packing_type == PackingType.PYINSTALLER


# ---------------------------------------------------------------------------
# 10. BinaryUnpacker.unpack -- 4 yol dispatch
# ---------------------------------------------------------------------------

def _fake_safe_run_success(
    cmd: Sequence[str], **kwargs: Any,
) -> "subprocess.CompletedProcess[str]":
    """safe_run mock: returncode=0 dondur."""
    return subprocess.CompletedProcess(
        args=list(cmd), returncode=0, stdout="UPX OK", stderr="",
    )


def _fake_safe_run_failure(
    cmd: Sequence[str], **kwargs: Any,
) -> "subprocess.CompletedProcess[str]":
    """safe_run mock: returncode=1 dondur."""
    return subprocess.CompletedProcess(
        args=list(cmd), returncode=1, stdout="", stderr="UPX failed",
    )


class TestBinaryUnpacker:
    def test_unpack_not_packed_returns_failure(
        self, tmp_path: Path, config: Config,
    ) -> None:
        bin_path = tmp_path / "x.bin"
        bin_path.write_bytes(b"plain")
        info = PackingInfo(
            is_packed=False, packing_type=PackingType.NONE, confidence=1.0,
        )
        unpacker = BinaryUnpacker(config)
        result = unpacker.unpack(bin_path, info, tmp_path / "out")
        assert result.success is False
        assert any("packed degil" in e for e in result.errors)

    def test_unpack_upx_success(
        self,
        tmp_path: Path,
        config: Config,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # UPX'i fake olarak resolve et + safe_run mock
        bin_path = tmp_path / "upx.bin"
        bin_path.write_bytes(b"FAKE UPX BINARY" * 100)

        monkeypatch.setattr(
            "karadul.analyzers.packed_binary.resolve_tool",
            lambda name: "/usr/bin/upx" if name == "upx" else None,
        )
        monkeypatch.setattr(
            "karadul.analyzers.packed_binary.safe_run",
            _fake_safe_run_success,
        )

        info = PackingInfo(
            is_packed=True, packing_type=PackingType.UPX, confidence=0.95,
        )
        unpacker = BinaryUnpacker(config)
        result = unpacker.unpack(bin_path, info, tmp_path / "out")
        assert result.success is True
        assert result.packing_type == PackingType.UPX
        assert len(result.extracted_files) == 1

    def test_unpack_upx_tool_missing(
        self,
        tmp_path: Path,
        config: Config,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        bin_path = tmp_path / "upx.bin"
        bin_path.write_bytes(b"\x00" * 100)

        monkeypatch.setattr(
            "karadul.analyzers.packed_binary.resolve_tool",
            lambda name: None,
        )

        info = PackingInfo(
            is_packed=True, packing_type=PackingType.UPX, confidence=0.95,
        )
        unpacker = BinaryUnpacker(config)
        result = unpacker.unpack(bin_path, info, tmp_path / "out")
        assert result.success is False
        assert any("UPX bulunamadi" in e for e in result.errors)

    def test_unpack_upx_failure_propagated(
        self,
        tmp_path: Path,
        config: Config,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        bin_path = tmp_path / "upx.bin"
        bin_path.write_bytes(b"\x00" * 100)

        monkeypatch.setattr(
            "karadul.analyzers.packed_binary.resolve_tool",
            lambda name: "/usr/bin/upx",
        )
        monkeypatch.setattr(
            "karadul.analyzers.packed_binary.safe_run",
            _fake_safe_run_failure,
        )

        info = PackingInfo(
            is_packed=True, packing_type=PackingType.UPX, confidence=0.95,
        )
        unpacker = BinaryUnpacker(config)
        result = unpacker.unpack(bin_path, info, tmp_path / "out")
        assert result.success is False
        assert any("UPX decompress basarisiz" in e for e in result.errors)

    def test_unpack_nuitka_metadata(
        self, tmp_path: Path, config: Config,
    ) -> None:
        bin_path = tmp_path / "n.bin"
        bin_path.write_bytes(
            b"\x00" * 100
            + b"__nuitka_module"
            + b"\x00" * 100
            + b"foo.py"
            + b"\x00"
        )
        info = PackingInfo(
            is_packed=True, packing_type=PackingType.NUITKA, confidence=0.85,
        )
        unpacker = BinaryUnpacker(config)
        result = unpacker.unpack(bin_path, info, tmp_path / "out")
        assert result.success is True
        # Metadata JSON cikarilmali
        meta_files = [
            ef for ef in result.extracted_files
            if ef.original_name == "nuitka_metadata.json"
        ]
        assert len(meta_files) == 1
        assert meta_files[0].path.exists()

    def test_unpack_generic_fallback(
        self, tmp_path: Path, config: Config,
    ) -> None:
        bin_path = tmp_path / "g.bin"
        bin_path.write_bytes(_make_random_high_entropy(65536 * 3))
        info = PackingInfo(
            is_packed=True, packing_type=PackingType.UNKNOWN_PACKED, confidence=0.7,
        )
        unpacker = BinaryUnpacker(config)
        result = unpacker.unpack(bin_path, info, tmp_path / "out")
        # En azindan bir section/blok cikarilmali
        assert len(result.extracted_files) >= 1


# ---------------------------------------------------------------------------
# 11. analyze_packed_binary -- public API smoke
# ---------------------------------------------------------------------------

class TestAnalyzePackedBinary:
    def test_plain_binary_no_unpack(self, tmp_path: Path) -> None:
        bin_path = tmp_path / "plain.bin"
        bin_path.write_bytes(b"A" * 65536)
        result = analyze_packed_binary(bin_path, output_dir=tmp_path / "out")
        assert "packing" in result
        assert result["packing"]["is_packed"] is False
        assert result["unpack"] is None

    def test_upx_binary_full_pipeline(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        bin_path = tmp_path / "upx.bin"
        bin_path.write_bytes(b"\x00" * 256 + UPX_MAGIC + b"\x00" * 1024)

        monkeypatch.setattr(
            "karadul.analyzers.packed_binary.resolve_tool",
            lambda name: "/usr/bin/upx" if name == "upx" else None,
        )
        monkeypatch.setattr(
            "karadul.analyzers.packed_binary.safe_run",
            _fake_safe_run_success,
        )

        result = analyze_packed_binary(bin_path, output_dir=tmp_path / "out")
        assert result["packing"]["is_packed"] is True
        assert result["packing"]["packing_type"] == "upx"
        assert result["unpack"] is not None
        assert result["unpack"]["success"] is True

    def test_default_config_used_when_none(self, tmp_path: Path) -> None:
        bin_path = tmp_path / "x.bin"
        bin_path.write_bytes(b"\x00" * 1024)
        # config=None ile cagri (Config() varsayilan kullanilir)
        result = analyze_packed_binary(bin_path)
        assert "packing" in result


# ---------------------------------------------------------------------------
# 12. GUVENLIK: safe_zlib_decompress 100MB bomb defense
# ---------------------------------------------------------------------------

class TestSecurityZipBomb:
    """100MB limit + kucuk-input/buyuk-output bomb tespiti."""

    def test_safe_zlib_normal_decompress(self) -> None:
        # Normal sikistirma -> basari
        from karadul.core.safe_subprocess import safe_zlib_decompress
        original = b"hello world" * 100
        compressed = zlib.compress(original)
        out = safe_zlib_decompress(compressed, max_size=10_000)
        assert out == original

    def test_safe_zlib_blocks_oversize(self) -> None:
        # 1KB decompressed veriyi 100B sinirla red et
        from karadul.core.safe_subprocess import safe_zlib_decompress
        original = b"A" * 1024
        compressed = zlib.compress(original)
        out = safe_zlib_decompress(compressed, max_size=100)
        assert out is None  # Bomb sayildi

    def test_zip_bomb_small_input_huge_output_blocked(self) -> None:
        # Klasik bomb: 1KB sikistirilmis -> 200MB hedef (limit 100MB)
        from karadul.core.safe_subprocess import safe_zlib_decompress
        # 200MB "A" karakteri tek byte'a yuksek oranda sikistirilir
        bomb_payload = b"A" * (200 * 1024 * 1024)
        compressed = zlib.compress(bomb_payload)
        # compressed boyut ~200KB ama uncompressed 200MB
        assert len(compressed) < 1 * 1024 * 1024  # Bomb yapisi onayi
        out = safe_zlib_decompress(
            compressed, max_size=_MAX_PYINSTALLER_DECOMPRESS,
        )
        assert out is None

    def test_safe_zlib_invalid_data_returns_none(self) -> None:
        from karadul.core.safe_subprocess import safe_zlib_decompress
        assert safe_zlib_decompress(b"NOT-ZLIB", max_size=1024) is None

    def test_pyinstaller_max_decompress_constant(self) -> None:
        # Modul sabiti 100MB olmali (CRITICAL-3 koruma)
        assert _MAX_PYINSTALLER_DECOMPRESS == 100 * 1024 * 1024


# ---------------------------------------------------------------------------
# 13. GUVENLIK: Path traversal (PyInstaller TOC name)
# ---------------------------------------------------------------------------

class TestSecurityPathTraversal:
    """TOC entry name'i ../ veya absolute path olamaz."""

    def test_dotdot_traversal_normalized_or_rejected(
        self, tmp_path: Path,
    ) -> None:
        # ../../etc/passwd gibi name -> .. partlari kaldirilir, dosya yine
        # output_dir icinde kalir veya None doner.
        data = b"X" * 1024
        entry = {
            "name": "../../etc/passwd",
            "entry_offset": 0,
            "data_length": 16,
            "uncompressed_length": 16,
            "is_compressed": False,
            "type_flag": ord("d"),
            "type_name": "DATA",
        }
        out = tmp_path / "stage"
        out.mkdir()
        result = PyInstallerExtractor._extract_entry(
            data=data, pkg_start=0, entry=entry, output_dir=out,
        )
        # Path traversal engellenmeli: ya None, ya da sadece "etc/passwd" olarak
        # output_dir icinde yazildi.
        if result is not None:
            assert str(result.path).startswith(str(out.resolve()))
            # "/etc/passwd" gibi sistem yoluna yazilmadi
            assert not str(result.path).startswith("/etc/")

    def test_absolute_path_stripped(self, tmp_path: Path) -> None:
        # /etc/passwd -> "etc/passwd" olarak goz altina alinir
        data = b"X" * 1024
        entry = {
            "name": "/etc/passwd",
            "entry_offset": 0,
            "data_length": 16,
            "uncompressed_length": 16,
            "is_compressed": False,
            "type_flag": ord("d"),
            "type_name": "DATA",
        }
        out = tmp_path / "stage"
        out.mkdir()
        result = PyInstallerExtractor._extract_entry(
            data=data, pkg_start=0, entry=entry, output_dir=out,
        )
        if result is not None:
            # Yazma output_dir icinde olmali
            resolved = result.path.resolve()
            assert str(resolved).startswith(str(out.resolve()))

    def test_prefix_confusion_blocked(self, tmp_path: Path) -> None:
        # Output_dir = /tmp/stage; saldirgan name = ../stage-evil/xxx denemesi
        # Path.relative_to ile reddedilmeli.
        out = tmp_path / "stage"
        out.mkdir()
        # Komsu evil dizini olustur
        evil = tmp_path / "stage-evil"
        evil.mkdir()

        # Manipule edilmis name: ../stage-evil/leak.txt
        # Normalize sonrasi: "stage-evil/leak.txt" -- output_dir disinda kalir
        data = b"X" * 1024
        entry = {
            "name": "../stage-evil/leak.txt",
            "entry_offset": 0,
            "data_length": 8,
            "uncompressed_length": 8,
            "is_compressed": False,
            "type_flag": ord("d"),
            "type_name": "DATA",
        }
        result = PyInstallerExtractor._extract_entry(
            data=data, pkg_start=0, entry=entry, output_dir=out,
        )
        # Dosya evil dizinine yazilmamis olmali
        assert not (evil / "leak.txt").exists()
        # Eger result varsa, kesinlikle output_dir altinda olmali
        if result is not None:
            resolved = result.path.resolve()
            assert str(resolved).startswith(str(out.resolve()))


# ---------------------------------------------------------------------------
# 14. GUVENLIK: Windows reserved names
# ---------------------------------------------------------------------------

class TestSecurityWindowsReserved:
    """CON, PRN, COM1, LPT1 gibi isimler engellenmeli."""

    def test_is_windows_reserved_top_level(self) -> None:
        assert _is_windows_reserved("CON")
        assert _is_windows_reserved("PRN")
        assert _is_windows_reserved("AUX")
        assert _is_windows_reserved("NUL")
        assert _is_windows_reserved("COM1")
        assert _is_windows_reserved("LPT9")

    def test_is_windows_reserved_with_extension(self) -> None:
        # CON.txt, PRN.dll de engellenmeli
        assert _is_windows_reserved("CON.txt")
        assert _is_windows_reserved("PRN.dll")
        assert _is_windows_reserved("COM3.log")

    def test_is_windows_reserved_case_insensitive(self) -> None:
        assert _is_windows_reserved("con")
        assert _is_windows_reserved("Aux")
        assert _is_windows_reserved("CoM2")

    def test_is_windows_reserved_in_path_component(self) -> None:
        # Multi-component path
        assert _is_windows_reserved("subdir/CON.pyc")
        assert _is_windows_reserved("a/b/PRN")
        assert _is_windows_reserved("subdir\\LPT9.data")

    def test_normal_names_not_reserved(self) -> None:
        assert not _is_windows_reserved("normal.txt")
        assert not _is_windows_reserved("a/b/c.py")
        # CON prefix ama tam eslesme degil
        assert not _is_windows_reserved("console.log")
        assert not _is_windows_reserved("comma.txt")
        assert not _is_windows_reserved("auxiliary.bin")

    def test_extract_entry_blocks_con_pyc(self, tmp_path: Path) -> None:
        # PyInstaller TOC entry: name = CON.pyc -> reddedilmeli
        data = b"X" * 1024
        entry = {
            "name": "CON.pyc",
            "entry_offset": 0,
            "data_length": 32,
            "uncompressed_length": 32,
            "is_compressed": False,
            "type_flag": ord("s"),
            "type_name": "SCRIPT",
        }
        result = PyInstallerExtractor._extract_entry(
            data=data, pkg_start=0, entry=entry, output_dir=tmp_path,
        )
        assert result is None
        # Diskte CON.pyc dosyasi YOK
        assert not (tmp_path / "CON.pyc").exists()

    def test_extract_entry_blocks_nested_aux(self, tmp_path: Path) -> None:
        # subdir/AUX.dll gibi nested reserved name
        data = b"X" * 1024
        entry = {
            "name": "subdir/AUX.dll",
            "entry_offset": 0,
            "data_length": 16,
            "uncompressed_length": 16,
            "is_compressed": False,
            "type_flag": ord("b"),
            "type_name": "BINARY",
        }
        result = PyInstallerExtractor._extract_entry(
            data=data, pkg_start=0, entry=entry, output_dir=tmp_path,
        )
        assert result is None

    def test_reserved_set_completeness(self) -> None:
        # Frozenset CON/PRN/AUX/NUL + COM1-9 + LPT1-9 = 4 + 9 + 9 = 22
        assert len(_WINDOWS_RESERVED_NAMES) == 22
        assert "CON" in _WINDOWS_RESERVED_NAMES
        assert "COM5" in _WINDOWS_RESERVED_NAMES
        assert "LPT7" in _WINDOWS_RESERVED_NAMES


# ---------------------------------------------------------------------------
# 15. Dataclass to_dict serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_packing_info_to_dict_round_trip(self) -> None:
        info = PackingInfo(
            is_packed=True,
            packing_type=PackingType.UPX,
            confidence=0.9512345,
            evidence=["UPX magic bulundu"],
            section_entropies=[
                SectionEntropy(
                    name=".text", offset=0x1000, size=4096,
                    entropy=7.123456, is_packed=True,
                ),
            ],
            overall_entropy=7.5,
            metadata={"upx_offset": 256},
        )
        d = info.to_dict()
        assert d["is_packed"] is True
        assert d["packing_type"] == "upx"
        assert d["confidence"] == 0.951
        assert d["section_entropies"][0]["name"] == ".text"
        assert d["section_entropies"][0]["entropy"] == 7.1235
        assert d["metadata"]["upx_offset"] == 256

    def test_unpack_result_to_dict(self, tmp_path: Path) -> None:
        ef = ExtractedFile(
            path=tmp_path / "x.pyc",
            original_name="x.pyc",
            file_type="pyc",
            size=128,
            metadata={"k": "v"},
        )
        res = UnpackResult(
            success=True,
            packing_type=PackingType.PYINSTALLER,
            extracted_files=[ef],
            errors=["minor"],
            duration_seconds=1.234567,
            output_dir=tmp_path,
        )
        d = res.to_dict()
        assert d["success"] is True
        assert d["packing_type"] == "pyinstaller"
        assert d["extracted_count"] == 1
        assert d["duration_seconds"] == 1.235
        assert d["output_dir"] == str(tmp_path)

    def test_unpack_result_none_output_dir(self) -> None:
        res = UnpackResult(
            success=False,
            packing_type=PackingType.NONE,
            output_dir=None,
        )
        d = res.to_dict()
        assert d["output_dir"] is None
