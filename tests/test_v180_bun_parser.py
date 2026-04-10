"""v1.8.0 BUN Segment Parser testleri.

Bun compiled binary tespiti ve __BUN segmentinden JS extraction.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.core.target import Language, TargetDetector, TargetInfo, TargetType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_macho_bytes(extra: bytes = b"") -> bytes:
    """Minimal Mach-O 64-bit header bytes (little-endian) + ek veri."""
    # MH_MAGIC_64 = 0xFEEDFACF -> LE: CF FA ED FE
    magic = b"\xcf\xfa\xed\xfe"
    cpu_type = b"\x07\x00\x00\x01"  # x86_64
    cpu_subtype = b"\x03\x00\x00\x00"
    filetype = b"\x02\x00\x00\x00"  # MH_EXECUTE
    ncmds = b"\x00\x00\x00\x00"
    sizeofcmds = b"\x00\x00\x00\x00"
    flags = b"\x00\x00\x00\x00"
    reserved = b"\x00\x00\x00\x00"
    header = magic + cpu_type + cpu_subtype + filetype + ncmds + sizeofcmds + flags + reserved
    padding = b"\x00" * (64 - len(header))
    return header + padding + extra


@pytest.fixture
def detector() -> TargetDetector:
    """Fresh TargetDetector instance."""
    return TargetDetector()


@pytest.fixture
def plain_macho_file(tmp_path: Path) -> Path:
    """__BUN segmenti OLMAYAN normal Mach-O binary."""
    f = tmp_path / "plain_binary"
    f.write_bytes(_make_macho_bytes(b"\x00" * 256))
    return f


@pytest.fixture
def bun_macho_file(tmp_path: Path) -> Path:
    """__BUN segmenti OLAN Mach-O binary (header icinde __BUN string'i var)."""
    # __BUN string'ini header'dan sonra gom — fallback detection bunu arar
    extra = b"__BUN" + b"\x00" * 251
    f = tmp_path / "bun_binary"
    f.write_bytes(_make_macho_bytes(extra))
    return f


# ---------------------------------------------------------------------------
# 1. TargetType enum var mi
# ---------------------------------------------------------------------------

class TestBunTargetType:
    """BUN_BINARY target type varligini dogrula."""

    def test_bun_binary_enum_exists(self):
        assert hasattr(TargetType, "BUN_BINARY")
        assert TargetType.BUN_BINARY.value == "bun_binary"

    def test_bun_binary_in_target_types(self):
        all_values = [t.value for t in TargetType]
        assert "bun_binary" in all_values


# ---------------------------------------------------------------------------
# 2. Target Detection — lief mock ile
# ---------------------------------------------------------------------------

class TestBunTargetDetection:
    """__BUN segmenti olan/olmayan binary tespiti."""

    def test_bun_detected_with_lief(self, tmp_path: Path, detector: TargetDetector):
        """lief ile __BUN segmenti olan binary -> BUN_BINARY."""
        # Gercek Mach-O header
        binary_file = tmp_path / "bun_app"
        binary_file.write_bytes(_make_macho_bytes(b"\x00" * 256))

        # lief mock: segments listesinde __BUN olan binary
        mock_seg_text = MagicMock()
        mock_seg_text.name = "__TEXT"
        mock_seg_bun = MagicMock()
        mock_seg_bun.name = "__BUN"

        mock_binary = MagicMock()
        mock_binary.segments = [mock_seg_text, mock_seg_bun]

        with patch("karadul.core.target.lief", create=True) as mock_lief:
            # lief modulu import edildiginde mock donsun
            import sys
            mock_lief_module = MagicMock()
            mock_lief_module.parse.return_value = mock_binary

            with patch.dict(sys.modules, {"lief": mock_lief_module}):
                # _has_bun_segment icinde import lief yapilacak
                info = detector.detect(binary_file)

        assert info.target_type == TargetType.BUN_BINARY
        assert info.language == Language.JAVASCRIPT

    def test_no_bun_segment_stays_macho(self, plain_macho_file: Path, detector: TargetDetector):
        """__BUN segmenti olmayan binary -> MACHO_BINARY kalir."""
        # lief mock: sadece __TEXT segmenti
        mock_seg_text = MagicMock()
        mock_seg_text.name = "__TEXT"

        mock_binary = MagicMock()
        mock_binary.segments = [mock_seg_text]

        import sys
        mock_lief_module = MagicMock()
        mock_lief_module.parse.return_value = mock_binary

        with patch.dict(sys.modules, {"lief": mock_lief_module}):
            info = detector.detect(plain_macho_file)

        assert info.target_type == TargetType.MACHO_BINARY

    def test_bun_fallback_raw_bytes(self, bun_macho_file: Path, detector: TargetDetector):
        """lief yoksa fallback: raw bytes'ta __BUN stringi -> BUN_BINARY."""
        import sys

        # lief import'u ImportError firlatsin
        original_modules = sys.modules.copy()

        # lief'i sil ki ImportError firlatsin
        with patch.dict(sys.modules, {"lief": None}):
            # import lief -> ImportError olacak (None modulu import edilemez)
            # Ama _has_bun_segment bu durumda fallback kullanir
            # Fallback: raw bytes'ta __BUN arar
            info = detector.detect(bun_macho_file)

        assert info.target_type == TargetType.BUN_BINARY

    def test_bun_metadata_has_flag(self, tmp_path: Path, detector: TargetDetector):
        """BUN binary metadata'sinda bun_compiled=True olmali."""
        binary_file = tmp_path / "bun_test"
        binary_file.write_bytes(_make_macho_bytes(b"\x00" * 256))

        mock_seg_bun = MagicMock()
        mock_seg_bun.name = "__BUN"

        mock_binary = MagicMock()
        mock_binary.segments = [mock_seg_bun]

        import sys
        mock_lief_module = MagicMock()
        mock_lief_module.parse.return_value = mock_binary

        with patch.dict(sys.modules, {"lief": mock_lief_module}):
            info = detector.detect(binary_file)

        assert info.metadata.get("bun_compiled") is True


# ---------------------------------------------------------------------------
# 3. JS Extraction — zlib compressed
# ---------------------------------------------------------------------------

class TestBunJsExtraction:
    """__BUN segmentinden JS extraction testleri."""

    def test_zlib_compressed_extraction(self, tmp_path: Path):
        """zlib compressed __BUN segment -> decompress edilmis JS."""
        from karadul.config import Config
        from karadul.core.workspace import Workspace

        js_source = b"console.log('hello from bun')"
        compressed = zlib.compress(js_source)

        # Fake binary: header + padding + compressed data
        header = _make_macho_bytes()
        padding_before = b"\x00" * 128  # segment oncesi bosluk
        binary_data = header + padding_before + compressed + b"\x00" * 64

        binary_file = tmp_path / "bun_compressed"
        binary_file.write_bytes(binary_data)

        # Mock lief segment
        mock_seg_bun = MagicMock()
        mock_seg_bun.name = "__BUN"
        mock_seg_bun.file_offset = len(header) + len(padding_before)
        mock_seg_bun.file_size = len(compressed)

        mock_binary = MagicMock()
        mock_binary.segments = [mock_seg_bun]

        import sys
        mock_lief_module = MagicMock()
        mock_lief_module.parse.return_value = mock_binary
        mock_lief_module.lief = mock_lief_module

        # Workspace olustur
        config = Config()
        ws = Workspace(target_name="bun_test", base_dir=tmp_path / "workspace")

        from karadul.analyzers.macho import MachOAnalyzer

        analyzer = MachOAnalyzer(config)

        with patch.dict(sys.modules, {"lief": mock_lief_module}):
            result = analyzer._extract_bun_js(binary_file, ws)

        assert result is not None
        assert result.exists()
        assert result.name == "bun_bundle.js"
        content = result.read_bytes()
        assert content == js_source

    def test_raw_uncompressed_extraction(self, tmp_path: Path):
        """Compress edilmemis __BUN segment -> raw bytes kaydedilir."""
        from karadul.config import Config
        from karadul.core.workspace import Workspace

        js_source = b"console.log('raw bun bundle')"

        # Compress edilmemis data (zlib decompress basarisiz olacak)
        header = _make_macho_bytes()
        padding = b"\x00" * 128
        binary_data = header + padding + js_source + b"\x00" * 64

        binary_file = tmp_path / "bun_raw"
        binary_file.write_bytes(binary_data)

        mock_seg_bun = MagicMock()
        mock_seg_bun.name = "__BUN"
        mock_seg_bun.file_offset = len(header) + len(padding)
        mock_seg_bun.file_size = len(js_source)

        mock_binary = MagicMock()
        mock_binary.segments = [mock_seg_bun]

        import sys
        mock_lief_module = MagicMock()
        mock_lief_module.parse.return_value = mock_binary

        # zlib.error mock'u icin gercek zlib kullan — raw JS zlib decode
        # edemeyecek, boylece fallback devreye girecek
        config = Config()
        ws = Workspace(target_name="bun_raw_test", base_dir=tmp_path / "workspace")

        from karadul.analyzers.macho import MachOAnalyzer

        analyzer = MachOAnalyzer(config)

        with patch.dict(sys.modules, {"lief": mock_lief_module}):
            result = analyzer._extract_bun_js(binary_file, ws)

        assert result is not None
        assert result.exists()
        content = result.read_bytes()
        assert content == js_source

    def test_corrupt_segment_returns_none(self, tmp_path: Path):
        """Corrupt/bos segment -> None donmeli."""
        from karadul.config import Config
        from karadul.core.workspace import Workspace

        # Cok kisa binary — segment offset dosya disinda
        binary_file = tmp_path / "bun_corrupt"
        binary_file.write_bytes(_make_macho_bytes())

        mock_seg_bun = MagicMock()
        mock_seg_bun.name = "__BUN"
        mock_seg_bun.file_offset = 99999  # Dosya disinda
        mock_seg_bun.file_size = 50000

        mock_binary = MagicMock()
        mock_binary.segments = [mock_seg_bun]

        import sys
        mock_lief_module = MagicMock()
        mock_lief_module.parse.return_value = mock_binary

        config = Config()
        ws = Workspace(target_name="bun_corrupt_test", base_dir=tmp_path / "workspace")

        from karadul.analyzers.macho import MachOAnalyzer

        analyzer = MachOAnalyzer(config)

        with patch.dict(sys.modules, {"lief": mock_lief_module}):
            result = analyzer._extract_bun_js(binary_file, ws)

        assert result is None

    def test_no_lief_returns_none(self, tmp_path: Path):
        """lief kurulu degilse -> None donmeli."""
        from karadul.config import Config
        from karadul.core.workspace import Workspace

        binary_file = tmp_path / "bun_nolief"
        binary_file.write_bytes(_make_macho_bytes())

        config = Config()
        ws = Workspace(target_name="bun_nolief_test", base_dir=tmp_path / "workspace")

        from karadul.analyzers.macho import MachOAnalyzer

        analyzer = MachOAnalyzer(config)

        import sys
        # lief import'u ImportError firlatsin
        with patch.dict(sys.modules, {"lief": None}):
            # sys.modules'ta None olan modul import edilince ImportError firlatir
            result = analyzer._extract_bun_js(binary_file, ws)

        assert result is None

    def test_lief_parse_returns_none(self, tmp_path: Path):
        """lief.parse None donerse -> None donmeli."""
        from karadul.config import Config
        from karadul.core.workspace import Workspace

        binary_file = tmp_path / "bun_badbinary"
        binary_file.write_bytes(b"\x00" * 64)

        import sys
        mock_lief_module = MagicMock()
        mock_lief_module.parse.return_value = None

        config = Config()
        ws = Workspace(target_name="bun_bad_test", base_dir=tmp_path / "workspace")

        from karadul.analyzers.macho import MachOAnalyzer

        analyzer = MachOAnalyzer(config)

        with patch.dict(sys.modules, {"lief": mock_lief_module}):
            result = analyzer._extract_bun_js(binary_file, ws)

        assert result is None


# ---------------------------------------------------------------------------
# 4. Analyzer Registration
# ---------------------------------------------------------------------------

class TestBunAnalyzerRegistration:
    """BUN_BINARY icin analyzer kayitli olmali."""

    def test_bun_binary_registered(self):
        from karadul.analyzers import get_analyzer
        from karadul.analyzers.macho import MachOAnalyzer

        analyzer_cls = get_analyzer(TargetType.BUN_BINARY)
        assert analyzer_cls is MachOAnalyzer


# ---------------------------------------------------------------------------
# 5. Case insensitive segment name (__bun vs __BUN)
# ---------------------------------------------------------------------------

class TestBunCaseInsensitive:
    """Bun segment adi buyuk/kucuk harf farketmemeli."""

    def test_lowercase_bun_segment(self, tmp_path: Path, detector: TargetDetector):
        """__bun (kucuk harf) segmenti de tespit edilmeli."""
        binary_file = tmp_path / "bun_lower"
        binary_file.write_bytes(_make_macho_bytes(b"\x00" * 256))

        mock_seg = MagicMock()
        mock_seg.name = "__bun"

        mock_binary = MagicMock()
        mock_binary.segments = [mock_seg]

        import sys
        mock_lief_module = MagicMock()
        mock_lief_module.parse.return_value = mock_binary

        with patch.dict(sys.modules, {"lief": mock_lief_module}):
            info = detector.detect(binary_file)

        assert info.target_type == TargetType.BUN_BINARY
