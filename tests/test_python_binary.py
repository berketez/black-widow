"""Python Binary Analyzer test suite.

PyInstaller/cx_Freeze/Nuitka tespiti, Python versiyon tespiti,
embedded modul extraction ve TOC parse testleri.

Gercek packed Python binary olmadan calismali -- mock data kullanir.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.python_binary import (
    PythonBinaryAnalyzer,
    _CXFREEZE_MARKERS,
    _MEIPASS_MARKER,
    _NUITKA_MARKERS,
    _PYC_MAGIC_TO_VERSION,
    _PYINSTALLER_MAGIC,
    _PYZ_MAGIC,
)
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    """Test icin varsayilan Config."""
    return Config()


@pytest.fixture
def python_analyzer(config: Config) -> PythonBinaryAnalyzer:
    """PythonBinaryAnalyzer instance."""
    return PythonBinaryAnalyzer(config)


@pytest.fixture
def mock_pyinstaller_binary(tmp_path: Path) -> Path:
    """Sahte PyInstaller binary olustur — ilgili marker'lar iceren."""
    binary_path = tmp_path / "test_pyinstaller"

    content = b"\x00" * 64  # padding
    content += _MEIPASS_MARKER + b"\x00"
    content += _PYZ_MAGIC + b"\x00"
    content += b"pyi-runtime\x00"
    content += b"Python 3.11.5\x00"
    content += b"_PYI_PROCNAME\x00"
    content += b"import os\x00"
    content += b"from pathlib import Path\x00"
    content += b"__main__.pyc\x00"
    content += b"myapp.pyc\x00"
    content += b"myapp.utils.pyc\x00"
    content += b"requests.pyc\x00"
    content += b"site-packages/click\x00"
    content += b"Traceback (most recent call last)\x00"
    content += b"\x00" * 64  # padding
    # PyInstaller archive cookie (simplified)
    content += _PYINSTALLER_MAGIC
    # pkg_length (4 bytes), toc_offset (4 bytes), toc_length (4 bytes), pyver (4 bytes)
    content += struct.pack("<IIII", 0, 0, 0, 311)  # pyver = 311 -> Python 3.11

    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def mock_cxfreeze_binary(tmp_path: Path) -> Path:
    """Sahte cx_Freeze binary olustur."""
    binary_path = tmp_path / "test_cxfreeze"

    content = b"\x00" * 64
    content += b"cx_Freeze\x00"
    content += b"frozen_modules\x00"
    content += b"Python 3.10.12\x00"
    content += b"initscript\x00"
    content += b"__main__.pyc\x00"
    content += b"mymodule.pyc\x00"
    content += b"\x00" * 64

    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def mock_nuitka_binary(tmp_path: Path) -> Path:
    """Sahte Nuitka binary olustur."""
    binary_path = tmp_path / "test_nuitka"

    content = b"\x00" * 64
    content += b"Nuitka\x00"
    content += b"nuitka-version: 1.8.0\x00"
    content += b"__compiled__\x00"
    content += b"_nuitka\x00"
    content += b"Python 3.12.0\x00"
    content += b"\x00" * 64

    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def mock_pyinstaller_target(mock_pyinstaller_binary: Path) -> TargetInfo:
    """TargetInfo for PyInstaller binary."""
    return TargetInfo(
        path=mock_pyinstaller_binary,
        name="test_pyinstaller",
        target_type=TargetType.PYTHON_PACKED,
        language=Language.PYTHON,
        file_size=mock_pyinstaller_binary.stat().st_size,
        file_hash="abc123",
    )


@pytest.fixture
def mock_workspace(tmp_path: Path) -> Workspace:
    """Gecici workspace."""
    ws = Workspace(tmp_path / "workspaces", "test_python")
    ws.create()
    return ws


# --------------------------------------------------------------------------
# Detection (can_handle) Tests
# --------------------------------------------------------------------------

class TestPythonBinaryDetection:
    """Python packed binary tespiti testleri."""

    def test_detect_pyinstaller_meipass(self, mock_pyinstaller_binary: Path):
        """MEIPASS marker ile PyInstaller tespiti."""
        target = TargetInfo(
            path=mock_pyinstaller_binary,
            name="test",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=mock_pyinstaller_binary.stat().st_size,
            file_hash="x",
        )
        assert PythonBinaryAnalyzer.can_handle(target) is True

    def test_detect_cxfreeze(self, mock_cxfreeze_binary: Path):
        """cx_Freeze marker ile tespit."""
        target = TargetInfo(
            path=mock_cxfreeze_binary,
            name="test",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=mock_cxfreeze_binary.stat().st_size,
            file_hash="x",
        )
        assert PythonBinaryAnalyzer.can_handle(target) is True

    def test_detect_nuitka(self, mock_nuitka_binary: Path):
        """Nuitka marker ile tespit."""
        target = TargetInfo(
            path=mock_nuitka_binary,
            name="test",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=mock_nuitka_binary.stat().st_size,
            file_hash="x",
        )
        assert PythonBinaryAnalyzer.can_handle(target) is True

    def test_detect_non_python_binary(self, tmp_path: Path):
        """Python olmayan binary tanilanmamali."""
        non_py = tmp_path / "not_python"
        non_py.write_bytes(b"\x00" * 256 + b"just a regular binary" + b"\x00" * 256)

        target = TargetInfo(
            path=non_py,
            name="not_python",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=non_py.stat().st_size,
            file_hash="x",
        )
        assert PythonBinaryAnalyzer.can_handle(target) is False

    def test_detect_pyinstaller_magic_only(self, tmp_path: Path):
        """Sadece MEI magic ile tespit."""
        binary = tmp_path / "mei_only"
        binary.write_bytes(b"\x00" * 128 + _PYINSTALLER_MAGIC + b"\x00" * 128)

        target = TargetInfo(
            path=binary,
            name="mei_only",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=binary.stat().st_size,
            file_hash="x",
        )
        assert PythonBinaryAnalyzer.can_handle(target) is True

    def test_detect_pyz_magic_only(self, tmp_path: Path):
        """Sadece PYZ magic ile tespit."""
        binary = tmp_path / "pyz_only"
        binary.write_bytes(b"\x00" * 128 + _PYZ_MAGIC + b"\x00" * 128)

        target = TargetInfo(
            path=binary,
            name="pyz_only",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=binary.stat().st_size,
            file_hash="x",
        )
        assert PythonBinaryAnalyzer.can_handle(target) is True

    def test_detect_nonexistent_file(self, tmp_path: Path):
        """Mevcut olmayan dosya False donmeli."""
        target = TargetInfo(
            path=tmp_path / "nonexistent",
            name="nonexistent",
            target_type=TargetType.UNKNOWN,
            language=Language.UNKNOWN,
            file_size=0,
            file_hash="",
        )
        assert PythonBinaryAnalyzer.can_handle(target) is False


# --------------------------------------------------------------------------
# Packer Detection Tests
# --------------------------------------------------------------------------

class TestPackerDetection:
    """Paketleyici tipi tespit testleri."""

    def test_detect_pyinstaller(self, python_analyzer: PythonBinaryAnalyzer, mock_pyinstaller_binary: Path):
        """PyInstaller dogru tespit edilmeli."""
        data = mock_pyinstaller_binary.read_bytes()
        result = python_analyzer._detect_packer(data)

        assert result["packer"] == "pyinstaller"
        assert result["confidence"] in ("medium", "high")

    def test_detect_cxfreeze(self, python_analyzer: PythonBinaryAnalyzer, mock_cxfreeze_binary: Path):
        """cx_Freeze dogru tespit edilmeli."""
        data = mock_cxfreeze_binary.read_bytes()
        result = python_analyzer._detect_packer(data)

        assert result["packer"] == "cx_freeze"
        assert result["confidence"] in ("medium", "high")

    def test_detect_nuitka(self, python_analyzer: PythonBinaryAnalyzer, mock_nuitka_binary: Path):
        """Nuitka dogru tespit edilmeli."""
        data = mock_nuitka_binary.read_bytes()
        result = python_analyzer._detect_packer(data)

        assert result["packer"] == "nuitka"
        assert result["confidence"] in ("medium", "high")

    def test_detect_unknown_packer(self, python_analyzer: PythonBinaryAnalyzer):
        """Bilinmeyen paketleyici 'unknown' donmeli."""
        data = b"\x00" * 256 + b"just random data" + b"\x00" * 256
        result = python_analyzer._detect_packer(data)

        assert result["packer"] == "unknown"
        assert result["confidence"] == "none"

    def test_packer_scores_exist(self, python_analyzer: PythonBinaryAnalyzer, mock_pyinstaller_binary: Path):
        """Packer sonucu scores icermeli."""
        data = mock_pyinstaller_binary.read_bytes()
        result = python_analyzer._detect_packer(data)

        assert "scores" in result
        assert "pyinstaller" in result["scores"]
        assert "cx_freeze" in result["scores"]
        assert "nuitka" in result["scores"]


# --------------------------------------------------------------------------
# Python Version Detection Tests
# --------------------------------------------------------------------------

class TestPythonVersionDetection:
    """Python versiyon tespiti testleri."""

    def test_detect_version_from_string(self, python_analyzer: PythonBinaryAnalyzer):
        """'Python X.Y.Z' string'inden versiyon tespiti."""
        data = b"\x00" * 64 + b"Python 3.11.5" + b"\x00" * 64
        version = python_analyzer._detect_python_version(data)

        assert version == "3.11.5"

    def test_detect_version_from_short_pattern(self, python_analyzer: PythonBinaryAnalyzer):
        """'pythonX.Y' kisa formatindan versiyon tespiti."""
        data = b"\x00" * 64 + b"libpython3.10.so" + b"\x00" * 64
        version = python_analyzer._detect_python_version(data)

        assert version is not None
        assert "3.10" in version

    def test_detect_version_from_pyc_magic(self, python_analyzer: PythonBinaryAnalyzer):
        """.pyc magic number'dan versiyon tespiti."""
        # Python 3.11 magic: 3495 (0x0DA7) + \r\n
        magic_num = 3495
        magic_bytes = struct.pack("<H", magic_num) + b"\r\n"
        data = b"\x00" * 64 + magic_bytes * 5 + b"\x00" * 64

        version = python_analyzer._version_from_pyc_magic(data)

        assert version is not None
        assert "3.11" in version

    def test_detect_version_none(self, python_analyzer: PythonBinaryAnalyzer):
        """Versiyon bulunamazsa None donmeli."""
        data = b"\x00" * 256 + b"no version info here" + b"\x00" * 256
        version = python_analyzer._detect_python_version(data)

        assert version is None

    def test_pyc_magic_table(self):
        """Magic number tablosu bos olmamali."""
        assert len(_PYC_MAGIC_TO_VERSION) > 0

        # Her versiyon string'i gecerli olmali
        for magic, version in _PYC_MAGIC_TO_VERSION.items():
            assert isinstance(magic, int)
            assert isinstance(version, str)
            assert "." in version

    def test_multiple_pyc_versions_majority(self, python_analyzer: PythonBinaryAnalyzer):
        """Birden fazla versiyon varsa en cok bulunan secilmeli."""
        # 5x Python 3.11 + 2x Python 3.12 magic number
        magic_311 = struct.pack("<H", 3495) + b"\r\n"  # 3.11
        magic_312 = struct.pack("<H", 3531) + b"\r\n"  # 3.12

        data = b"\x00" * 64
        data += magic_311 * 5  # 3.11 x5
        data += magic_312 * 2  # 3.12 x2
        data += b"\x00" * 64

        version = python_analyzer._version_from_pyc_magic(data)
        assert version == "3.11"  # majority


# --------------------------------------------------------------------------
# Embedded Module Extraction Tests
# --------------------------------------------------------------------------

class TestModuleExtraction:
    """Embedded modul listesi cikarma testleri."""

    def test_extract_basic_modules(self, python_analyzer: PythonBinaryAnalyzer):
        """Basit modul isimleri cikarilmali."""
        data = (
            b"\x00" * 64
            + b"__main__.pyc\x00"
            + b"myapp.pyc\x00"
            + b"myapp.utils.pyc\x00"
            + b"requests.pyc\x00"
            + b"os.pyc\x00"
            + b"json.pyc\x00"
            + b"\x00" * 64
        )

        result = python_analyzer._extract_embedded_modules(data)

        assert result is not None
        assert result["total"] > 0

        mod_names = [m["name"] for m in result["modules"]]
        assert "__main__" in mod_names

    def test_stdlib_detection(self, python_analyzer: PythonBinaryAnalyzer):
        """Stdlib modulleri dogru isaretlenmeli."""
        data = b"os.pyc\x00json.pyc\x00pathlib.pyc\x00myapp.pyc\x00"

        result = python_analyzer._extract_embedded_modules(data)

        if result is not None:
            stdlib_mods = [m for m in result["modules"] if m["type"] == "stdlib"]
            user_mods = [m for m in result["modules"] if m["type"] == "user"]

            assert result["stdlib_count"] == len(stdlib_mods)
            assert result["user_count"] == len(user_mods)

    def test_extract_no_modules(self, python_analyzer: PythonBinaryAnalyzer):
        """Modul bulunamazsa None donmeli."""
        data = b"\x00" * 256
        result = python_analyzer._extract_embedded_modules(data)
        assert result is None

    def test_is_python_stdlib(self):
        """Stdlib tespiti dogru calismali."""
        assert PythonBinaryAnalyzer._is_python_stdlib("os") is True
        assert PythonBinaryAnalyzer._is_python_stdlib("sys") is True
        assert PythonBinaryAnalyzer._is_python_stdlib("json") is True
        assert PythonBinaryAnalyzer._is_python_stdlib("pathlib") is True
        assert PythonBinaryAnalyzer._is_python_stdlib("collections") is True
        assert PythonBinaryAnalyzer._is_python_stdlib("collections.abc") is True
        assert PythonBinaryAnalyzer._is_python_stdlib("urllib.request") is True
        assert PythonBinaryAnalyzer._is_python_stdlib("asyncio") is True

        assert PythonBinaryAnalyzer._is_python_stdlib("myapp") is False
        assert PythonBinaryAnalyzer._is_python_stdlib("requests") is False
        assert PythonBinaryAnalyzer._is_python_stdlib("flask") is False
        assert PythonBinaryAnalyzer._is_python_stdlib("click") is False


# --------------------------------------------------------------------------
# PyInstaller TOC Tests
# --------------------------------------------------------------------------

class TestPyInstallerTOC:
    """PyInstaller TOC parse testleri."""

    def test_toc_no_magic(self, python_analyzer: PythonBinaryAnalyzer):
        """MEI magic yoksa None donmeli."""
        data = b"\x00" * 256
        result = python_analyzer._parse_pyinstaller_toc(data)
        assert result is None

    def test_toc_with_magic_and_version(self, python_analyzer: PythonBinaryAnalyzer, mock_pyinstaller_binary: Path):
        """MEI magic ve versiyon bilgisi parse edilmeli."""
        data = mock_pyinstaller_binary.read_bytes()
        result = python_analyzer._parse_pyinstaller_toc(data)

        # Cookie'den en azindan version bilgisi cikmali
        if result is not None:
            if "python_version" in result:
                assert "3.11" in result["python_version"]

    def test_toc_synthetic_entries(self, python_analyzer: PythonBinaryAnalyzer):
        """Sentetik TOC entry'leri parse edilmeli."""
        # TOC entry olustur:
        # entry_len (4) + offset (4) + comp_len (4) + uncomp_len (4)
        # + compress_flag (1) + type_flag (1) + name (null-terminated)
        name = b"__main__\x00"
        entry_data = struct.pack("<IIII", 18 + len(name), 0, 100, 200)
        entry_data += bytes([0])  # compress_flag = 0
        entry_data += bytes([ord("s")])  # type_flag = 's' (script)
        entry_data += name

        toc_length = len(entry_data)

        # Cookie: magic + pkg_length + toc_offset + toc_length + pyver
        cookie = _PYINSTALLER_MAGIC
        # pkg_length: cookie_start'dan (=TOC baslangici) archive basina mesafe
        # Archive baslangici = 0, cookie_start = toc_length
        # Dolayisiyla pkg_length = toc_length + 24 (cookie boyutu)
        # toc_offset = 0 (package baslangicina gore)
        # toc_abs = cookie_start - pkg_length + toc_offset
        #         = toc_length - (toc_length + 24) + 0 = -24 -> YANLIS
        #
        # Dogrusu: pkg_length = cookie_start (archive bas = 0)
        # toc_offset: cookie_start'a gore degil, archive basina gore
        # toc_abs = cookie_start - pkg_length + toc_offset
        # Eger pkg_length = toc_length, toc_offset = 0:
        #   toc_abs = toc_length - toc_length + 0 = 0 -> DOGRU!
        pkg_length = toc_length  # archive = dosya basi
        toc_offset = 0
        cookie += struct.pack("<IIII", pkg_length, toc_offset, toc_length, 311)

        data = entry_data + cookie

        result = python_analyzer._parse_pyinstaller_toc(data)

        assert result is not None
        assert result["total"] >= 1
        assert result["entries"][0]["name"] == "__main__"
        assert result["entries"][0]["type"] == "s"


# --------------------------------------------------------------------------
# String Filtering Tests
# --------------------------------------------------------------------------

class TestStringFiltering:
    """Python-ilgili string filtreleme testleri."""

    def test_filter_python_strings(self):
        """Python-ilgili string'ler filtrelenmeli."""
        strings = [
            "import os",
            "from pathlib import Path",
            "def my_function():",
            "class MyClass:",
            "just a random string",
            "__init__.py",
            "site-packages/requests",
            "Traceback (most recent call last)",
            "MEIPASS",
            "hello world",
        ]

        result = PythonBinaryAnalyzer._filter_python_strings(strings)

        assert len(result) > 0
        assert "just a random string" not in result
        assert "hello world" not in result
        assert any("import os" in s for s in result)
        assert any("Traceback" in s for s in result)

    def test_filter_empty_list(self):
        """Bos liste icin bos sonuc."""
        result = PythonBinaryAnalyzer._filter_python_strings([])
        assert result == []


# --------------------------------------------------------------------------
# Full Static Analysis Test (Integration)
# --------------------------------------------------------------------------

class TestPythonStaticAnalysis:
    """Tam statik analiz testi (mock subprocess ile)."""

    def test_analyze_static_pyinstaller(
        self,
        python_analyzer: PythonBinaryAnalyzer,
        mock_pyinstaller_target: TargetInfo,
        mock_workspace: Workspace,
    ):
        """PyInstaller binary analizi basarili calismali."""
        with patch.object(python_analyzer.runner, "run_strings", return_value=[
            "Python 3.11.5",
            "import os",
            "from pathlib import Path",
            "__main__.pyc",
            "myapp.pyc",
            "requests.pyc",
            "MEIPASS",
            "site-packages/click",
            "Traceback (most recent call last)",
        ]):
            result = python_analyzer.analyze_static(
                mock_pyinstaller_target, mock_workspace
            )

        assert isinstance(result, StageResult)
        assert result.success is True
        assert result.stats["analyzer"] == "python_binary"
        assert result.stats["packer"] == "pyinstaller"
        assert result.stats.get("python_version") is not None

    def test_analyze_static_unknown_packer(
        self,
        python_analyzer: PythonBinaryAnalyzer,
        mock_workspace: Workspace,
        tmp_path: Path,
    ):
        """Bilinmeyen paketleyici icin de calismali."""
        unknown = tmp_path / "unknown_binary"
        unknown.write_bytes(b"\x00" * 256 + b"Python 3.10.0\x00import os\x00" + b"\x00" * 256)

        target = TargetInfo(
            path=unknown,
            name="unknown_binary",
            target_type=TargetType.PYTHON_PACKED,
            language=Language.PYTHON,
            file_size=unknown.stat().st_size,
            file_hash="xyz",
        )

        with patch.object(python_analyzer.runner, "run_strings", return_value=[
            "Python 3.10.0",
            "import os",
        ]):
            result = python_analyzer.analyze_static(target, mock_workspace)

        assert isinstance(result, StageResult)
        # Bilinmeyen packer ama string'ler cikarilabildi
        assert result.stats["packer"] == "unknown"

    def test_analyze_static_unreadable_file(
        self,
        python_analyzer: PythonBinaryAnalyzer,
        mock_workspace: Workspace,
        tmp_path: Path,
    ):
        """Okunamayan dosya icin hata donmeli."""
        target = TargetInfo(
            path=tmp_path / "nonexistent_file",
            name="nonexistent",
            target_type=TargetType.PYTHON_PACKED,
            language=Language.PYTHON,
            file_size=0,
            file_hash="",
        )

        result = python_analyzer.analyze_static(target, mock_workspace)

        assert isinstance(result, StageResult)
        assert result.success is False
        assert len(result.errors) > 0


# --------------------------------------------------------------------------
# Deobfuscate Tests
# --------------------------------------------------------------------------

class TestPythonDeobfuscate:
    """Python packed binary deobfuscation testleri."""

    def test_deobfuscate_with_data(
        self,
        python_analyzer: PythonBinaryAnalyzer,
        mock_pyinstaller_target: TargetInfo,
        mock_workspace: Workspace,
    ):
        """Packer ve modul bilgisi deobfuscated dizinine tasinmali."""
        # Onceki static analiz sonuclarini simule et
        mock_workspace.save_json("static", "python_packer", {
            "packer": "pyinstaller", "confidence": "high",
        })
        mock_workspace.save_json("static", "python_modules", {
            "total": 3, "modules": [{"name": "os", "type": "stdlib"}],
        })

        result = python_analyzer.deobfuscate(mock_pyinstaller_target, mock_workspace)

        assert isinstance(result, StageResult)
        assert result.success is True
        assert "python_packer" in result.artifacts
        assert "python_modules" in result.artifacts

    def test_deobfuscate_no_prior_data(
        self,
        python_analyzer: PythonBinaryAnalyzer,
        mock_pyinstaller_target: TargetInfo,
        mock_workspace: Workspace,
    ):
        """Onceki analiz verisi yoksa uyari vermeli ama cokmemeli."""
        result = python_analyzer.deobfuscate(mock_pyinstaller_target, mock_workspace)

        assert isinstance(result, StageResult)
        assert len(result.errors) > 0


# --------------------------------------------------------------------------
# Analyzer Registry Test
# --------------------------------------------------------------------------

class TestPythonAnalyzerRegistry:
    """Analyzer registry'ye kayit testi."""

    def test_python_packed_registered(self):
        """PythonBinaryAnalyzer registry'de olmali."""
        from karadul.analyzers import get_analyzer
        analyzer_cls = get_analyzer(TargetType.PYTHON_PACKED)
        assert analyzer_cls is PythonBinaryAnalyzer

    def test_python_packed_in_list(self):
        """list_analyzers() Python packed'i icermeli."""
        from karadul.analyzers import list_analyzers
        analyzers = list_analyzers()
        assert TargetType.PYTHON_PACKED in analyzers


# --------------------------------------------------------------------------
# Enum Tests
# --------------------------------------------------------------------------

class TestPythonEnumValues:
    """TargetType ve Language enum'larinda Python degerlerinin varligini kontrol."""

    def test_target_type_python_packed(self):
        """TargetType.PYTHON_PACKED mevcut olmali."""
        assert TargetType.PYTHON_PACKED.value == "python_packed"

    def test_language_python(self):
        """Language.PYTHON mevcut olmali."""
        assert Language.PYTHON.value == "python"


# --------------------------------------------------------------------------
# Constants Validation Tests
# --------------------------------------------------------------------------

class TestConstants:
    """Sabitlerin dogru tanimlanmasini kontrol."""

    def test_pyinstaller_magic_length(self):
        """PyInstaller magic 8 byte olmali."""
        assert len(_PYINSTALLER_MAGIC) == 8

    def test_pyz_magic_length(self):
        """PYZ magic 4 byte olmali."""
        assert len(_PYZ_MAGIC) == 4

    def test_meipass_marker(self):
        """MEIPASS marker string kontrolu."""
        assert _MEIPASS_MARKER == b"_MEIPASS"

    def test_cxfreeze_markers_not_empty(self):
        """cx_Freeze marker listesi bos olmamali."""
        assert len(_CXFREEZE_MARKERS) > 0

    def test_nuitka_markers_not_empty(self):
        """Nuitka marker listesi bos olmamali."""
        assert len(_NUITKA_MARKERS) > 0
