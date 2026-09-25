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
    # PyInstaller archive cookie (simplified) -- gerçek biçim BIG-endian
    content += _PYINSTALLER_MAGIC
    # pkg_length (4 bytes), toc_offset (4 bytes), toc_length (4 bytes), pyver (4 bytes)
    content += struct.pack("!IIII", 0, 0, 0, 311)  # pyver = 311 -> Python 3.11

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

    def test_is_python_stdlib(self, python_analyzer: PythonBinaryAnalyzer):
        """String taraması stdlib'i tek sınıflandırıcıyla (classify_pyz_module) ayırır."""
        names = ["os", "sys", "json", "pathlib", "collections", "collections.abc",
                 "urllib.request", "asyncio", "myapp", "requests", "flask", "click"]
        data = b"\x00".join(n.encode() + b".pyc" for n in names)
        result = python_analyzer._extract_embedded_modules(data, "3.12")
        types = {m["name"]: m["type"] for m in result["modules"]}
        assert all(types[n] == "stdlib" for n in names[:8])
        assert all(types[n] == "user" for n in names[8:])


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
        """MEI magic ve cookie'deki sürüm (311 -> "3.11") okunmalı."""
        data = mock_pyinstaller_binary.read_bytes()
        result = python_analyzer._parse_pyinstaller_toc(data)

        assert result is not None
        assert result["python_version"] == "3.11"
        assert result["total"] == 0

    def test_toc_synthetic_entries(self, python_analyzer: PythonBinaryAnalyzer):
        """Sentetik TOC entry'leri parse edilmeli (gerçek biçim: big-endian)."""
        # TOC entry: entry_len (4) + offset (4) + comp_len (4) + uncomp_len (4)
        # + compress_flag (1) + type_flag (1) + name (null-terminated)
        name = b"__main__\x00"
        entry_data = struct.pack("!IIII", 18 + len(name), 0, 100, 200)
        entry_data += bytes([0])  # compress_flag = 0
        entry_data += bytes([ord("s")])  # type_flag = 's' (script)
        entry_data += name

        toc_length = len(entry_data)

        # Cookie TOC'nin hemen ardında: pkg_start = cookie - toc_offset - toc_length = 0.
        cookie = _PYINSTALLER_MAGIC
        cookie += struct.pack("!IIII", toc_length + 24, 0, toc_length, 311)

        data = entry_data + cookie

        result = python_analyzer._parse_pyinstaller_toc(data)

        assert result is not None
        assert result["total"] == 1
        assert result["entries"][0]["name"] == "__main__"
        assert result["entries"][0]["type"] == "s"
        assert result["python_version"] == "3.11"


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


# --------------------------------------------------------------------------
# Reconstruct + functions stat (kapsam genisligi: PyInstaller pipeline wiring)
# --------------------------------------------------------------------------

class TestPythonReconstruct:
    """PYTHON_PACKED functions stat + reconstruct.

    Kapsam bug'i: PYTHON_PACKED olu enum + PythonBinaryAnalyzer'da reconstruct/
    functions stat yoktu; packed_binary'nin gercek unpacker'i pipeline'a bagli
    degildi. Simdi analyze_static functions stat set eder, reconstruct PyInstaller
    CArchive'i (packed_binary.PyInstallerExtractor) acip python_project uretir.
    """

    def test_functions_stat_durust_na(
        self, python_analyzer, mock_pyinstaller_target, mock_workspace,
    ):
        """functions_found = "N/A": Python paketinde statik aşama fonksiyon saymaz.

        cli.py "Functions recovered" functions_found'u okur. Eskiden buraya arşivdeki
        TOPLAM modül sayısı yazılıyordu (gerçek hello: 109, 103'ü stdlib) -> yanıltıcı.
        Anahtar hiç yazılmasa cli.py "0" gösterirdi; "N/A" int olmadığı için "N/A"
        görünür. "functions" anahtarı yazılmaz: hacker_cli onu ":," ile biçimliyor.
        """
        result = python_analyzer.analyze_static(mock_pyinstaller_target, mock_workspace)
        st = result.stats
        assert st["functions_found"] == "N/A"
        assert "functions" not in st
        assert st["python_modules_total"] > 0  # mock 4 .pyc referansi iceriyor
        assert st["python_modules_total"] == (
            st["python_modules_user"] + st["python_modules_stdlib"]
            + st["python_modules_pyinstaller"])
        # cli.py sonuç tablosu kuralı: int değilse "N/A" (anahtar yoksa 0 derdi)
        shown = st.get("functions_found", st.get("ghidra_function_count", st.get("functions", 0)))
        assert not isinstance(shown, int)
        from karadul.hacker_cli import _stage_one_liner
        assert "functions" not in _stage_one_liner("static", st)   # ValueError da yok

    def test_reconstruct_produces_python_project(
        self, python_analyzer, mock_pyinstaller_target, mock_workspace,
    ):
        """reconstruct static sonrasi python_project + manifest.json uretmeli."""
        python_analyzer.analyze_static(mock_pyinstaller_target, mock_workspace)
        result = python_analyzer.reconstruct(mock_pyinstaller_target, mock_workspace)
        assert result is not None
        assert result.success
        assert "python_project" in result.artifacts
        assert (result.artifacts["python_project"] / "manifest.json").exists()

    def test_reconstruct_none_without_static(
        self, python_analyzer, mock_pyinstaller_target, mock_workspace,
    ):
        """Static analiz kosmadiysa reconstruct None doner (graceful).

        None -> ReconstructionStage bunu success=False'a cevirir; analiz JSON'u
        olmadan proje uretmeye calismaz.
        """
        result = python_analyzer.reconstruct(mock_pyinstaller_target, mock_workspace)
        assert result is None

    def test_reconstruct_survives_extractor_exception(
        self, python_analyzer, mock_pyinstaller_target, mock_workspace, monkeypatch,
    ):
        """PyInstallerExtractor.extract() RAISE ederse reconstruct graceful kalmali.

        MINOR-2: bir formatin unpacker'i patlasa bile stage olmemeli — python_project
        yine uretilir, hata yutulup errors'a yazilir. try/except (reconstruct) dalini pinler.
        """
        python_analyzer.analyze_static(mock_pyinstaller_target, mock_workspace)

        import karadul.analyzers.packed_binary as pb

        class _RaisingExtractor:
            def __init__(self, config):
                pass

            def extract(self, path, out):
                raise RuntimeError("boom-extract")

        monkeypatch.setattr(pb, "PyInstallerExtractor", _RaisingExtractor)

        result = python_analyzer.reconstruct(mock_pyinstaller_target, mock_workspace)
        assert result is not None
        assert result.success  # graceful: extraction hatasi pipeline'i oldurmez
        assert "python_project" in result.artifacts
        assert any("boom-extract" in e for e in result.errors)


class TestDecompilePycFiles:
    """_decompile_pyc_files: header onar + deterministik decompile (LLM/ML YOK)."""

    @staticmethod
    def _make_pyc(tmp_path: Path, name: str, src: str) -> Path:
        import marshal
        import sys
        from karadul.analyzers.pyc_decompiler import repair_pyc_header
        running = f"{sys.version_info.major}.{sys.version_info.minor}"
        body = marshal.dumps(compile(src, name, "exec"))
        p = tmp_path / name
        # Stripped govdeyi header'la onar -> gecerli .pyc (calisan surum)
        p.write_bytes(repair_pyc_header(body, running))
        return p

    def test_sadece_pyc_islenir_disasm_fallback(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path, monkeypatch
    ):
        """Sadece file_type=='pyc' islenir; pycdc yoksa disasm fallback (ayni surum)."""
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.packed_binary import ExtractedFile
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)  # hicbir arac yok

        pyc1 = self._make_pyc(tmp_path, "a.pyc", "def a():\n    return 1\n")
        pyc2 = self._make_pyc(tmp_path, "b.pyc", "def b():\n    return 2\n")
        so = tmp_path / "native.so"
        so.write_bytes(b"\x00" * 10)

        files = [
            ExtractedFile(path=pyc1, original_name="a.pyc", file_type="pyc", size=pyc1.stat().st_size),
            ExtractedFile(path=pyc2, original_name="b.pyc", file_type="pyc", size=pyc2.stat().st_size),
            ExtractedFile(path=so, original_name="native.so", file_type="so", size=10),
        ]
        out = tmp_path / "python_project"
        summary = python_analyzer._decompile_pyc_files(files, out)

        assert summary["total_pyc"] == 2       # .so DAHIL DEGIL (mutant: file_type filtre)
        assert summary["disasm"] == 2          # ayni surum -> stdlib dis calisir
        assert summary["decompiled"] == 0      # pycdc yok, gercek kaynak yok
        assert (out / "source").is_dir()

    def test_pycdc_ile_gercek_kaynak(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path, monkeypatch
    ):
        """pycdc mevcutsa .py kaynagi uretilir (decompiled sayacini pinler)."""
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.packed_binary import ExtractedFile
        monkeypatch.setattr(
            pd, "resolve_tool",
            lambda name, **k: "/fake/pycdc" if name == "pycdc" else None,
        )
        monkeypatch.setattr(
            pd, "_run_tool",
            lambda *a, **k: pd._ChildRun(0, b"def a():\n    return 1\n", b""),
        )
        pyc1 = self._make_pyc(tmp_path, "a.pyc", "def a():\n    return 1\n")
        files = [ExtractedFile(path=pyc1, original_name="a.pyc", file_type="pyc", size=pyc1.stat().st_size)]
        out = tmp_path / "python_project"
        summary = python_analyzer._decompile_pyc_files(files, out)

        assert summary["decompiled"] == 1
        assert summary["methods"].get("pycdc") == 1
        assert (out / "source" / "a.py").exists()
        assert "return 1" in (out / "source" / "a.py").read_text()

    def test_bos_liste(self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path):
        summary = python_analyzer._decompile_pyc_files([], tmp_path / "p")
        assert summary["total_pyc"] == 0
        assert summary["decompiled"] == 0

    def test_stripped_pyc_surum_parametresiyle(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path, monkeypatch
    ):
        """Header'i SIYRILMIS .pyc (PyInstaller davranisi) + py_version -> disasm calisir.

        Uctan uca fix regresyon korumasi: PyInstaller .pyc header'larini siyirir,
        surum header'dan okunamaz -> static asamada tespit edilen py_version'a duser.
        py_version VERILMEZSE onarim olmaz (failed); VERILINCE disasm calisir.
        Bu, `if global_version is None: global_version = py_version` fallback'ini pinler.
        """
        import marshal
        import sys
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.packed_binary import ExtractedFile
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)  # pycdc yok
        running = f"{sys.version_info.major}.{sys.version_info.minor}"

        # HEADER YOK -- ham marshal govdesi (repair uygulanmadan yazilir)
        body = marshal.dumps(compile("def z():\n    return 9\n", "z.py", "exec"))
        pyc = tmp_path / "z.pyc"
        pyc.write_bytes(body)
        files = [ExtractedFile(path=pyc, original_name="z.pyc", file_type="pyc", size=len(body))]

        # py_version YOK -> header onarilamaz -> cozulemez
        s_no = python_analyzer._decompile_pyc_files(files, tmp_path / "a")
        assert s_no["disasm"] == 0
        assert s_no["failed"] == 1

        # py_version VAR -> header onarilir -> disasm (ayni surum)
        s_yes = python_analyzer._decompile_pyc_files(files, tmp_path / "b", py_version=running)
        assert s_yes["disasm"] == 1
        assert s_yes["failed"] == 0


class TestCxFreezeExtraction:
    """_extract_cxfreeze: cx_Freeze library.zip + lib/ .pyc toplama."""

    @staticmethod
    def _real_pyc(src: str) -> bytes:
        import importlib.util
        import marshal
        import struct
        return importlib.util.MAGIC_NUMBER + struct.pack("<I", 0) * 3 + marshal.dumps(
            compile(src, "x.py", "exec"))

    def test_library_zip_ve_lib_serbest(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path, monkeypatch
    ):
        """library.zip icindeki + lib/ altindaki serbest .pyc'ler toplanir + decompile."""
        import sys
        import zipfile
        from karadul.analyzers import pyc_decompiler as pd
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)  # pycdc yok
        running = f"{sys.version_info.major}.{sys.version_info.minor}"

        app = tmp_path / "app"
        app.write_bytes(b"cx_Freeze\x00")
        lib = tmp_path / "lib"
        lib.mkdir()
        with zipfile.ZipFile(lib / "library.zip", "w") as zf:
            zf.writestr("app__main__.pyc", self._real_pyc("def m():\n    return 1\n"))
            zf.writestr("mymod/core.pyc", self._real_pyc("def c():\n    return 2\n"))
        (lib / "pkg").mkdir()
        (lib / "pkg" / "u.pyc").write_bytes(self._real_pyc("def u():\n    return 3\n"))

        extracted, _ = python_analyzer._extract_cxfreeze(app, tmp_path / "ext")
        # 2 (library.zip) + 1 (lib/ serbest) = 3 (mutant: .pyc filtre / lib tarama)
        assert len(extracted) == 3
        assert all(ef.file_type == "pyc" for ef in extracted)

        summary = python_analyzer._decompile_pyc_files(
            extracted, tmp_path / "proj", py_version=running)
        assert summary["total_pyc"] == 3
        assert summary["disasm"] == 3

    def test_dagitim_dizini_yoksa_bos(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path
    ):
        """Tek basina binary (lib/ yok) -> bos liste (graceful, patlamaz)."""
        app = tmp_path / "solo"
        app.write_bytes(b"cx_Freeze\x00")
        assert python_analyzer._extract_cxfreeze(app, tmp_path / "ext")[0] == []

    def test_zip_slip_korumasi(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path
    ):
        """library.zip'te ../ path -> output_dir DISINA yazilmaz (duzlestirme koruma)."""
        import zipfile
        app = tmp_path / "app"
        app.write_bytes(b"cx_Freeze\x00")
        lib = tmp_path / "lib"
        lib.mkdir()
        with zipfile.ZipFile(lib / "library.zip", "w") as zf:
            zf.writestr("../../evil.pyc", self._real_pyc("x = 1\n"))
        ext_dir = tmp_path / "ext"
        extracted, _ = python_analyzer._extract_cxfreeze(app, ext_dir)
        assert len(extracted) == 1
        # Cikan dosya ext_dir ALTINDA olmali, disari kacmamali
        assert ext_dir in extracted[0].path.parents
        assert not (tmp_path.parent / "evil.pyc").exists()
        assert not (tmp_path / "evil.pyc").exists()


class TestPycdcEntegrasyonu:
    """_decompile_pyc_files + pycdc (2026-09-25): kısmi çıktı sayımı, araç yolu, çıktı adı."""

    @staticmethod
    def _stripped(tmp_path: Path, name: str, src: str) -> Path:
        """PyInstaller TOC girdisi gibi: uzantısız ad + header'SIZ marshal gövdesi."""
        import marshal
        p = tmp_path / name
        p.write_bytes(marshal.dumps(compile(src, name, "exec")))
        return p

    def test_kismi_pycdc_decompiled_sayilmaz(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path, monkeypatch
    ):
        """pycdc rc=0 + 'Decompyle incomplete' -> partial (decompiled DEĞİL) + dürüst not."""
        import sys
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.packed_binary import ExtractedFile
        from karadul.analyzers.python_binary import _pyinstaller_note
        running = f"{sys.version_info.major}.{sys.version_info.minor}"
        monkeypatch.setattr(
            pd, "resolve_tool",
            lambda name, **k: "/fake/pycdc" if name == "pycdc" else None,
        )
        monkeypatch.setattr(
            pd, "_run_tool",
            lambda *a, **k: pd._ChildRun(
                0, b"def a():\n    pass\n# WARNING: Decompyle incomplete\n",
                b"Unsupported opcode: MAKE_CELL (225)\n"),
        )
        pyc = self._stripped(tmp_path, "hello", "def a():\n    return 1\n")
        files = [ExtractedFile(path=pyc, original_name="hello", file_type="pyc",
                               size=pyc.stat().st_size)]
        summary = python_analyzer._decompile_pyc_files(files, tmp_path / "proj", py_version=running)

        assert summary["decompiled"] == 0      # BUG: eskiden 1 (pycdc rc=0 başarı sanılıyordu)
        assert summary["partial"] == 1
        assert summary["disasm"] == 0 and summary["failed"] == 0  # sınıflar ayrık
        assert summary["pycdc_available"] is True
        assert (tmp_path / "proj" / "source" / "hello.partial.py").exists()
        note = _pyinstaller_note(summary)
        assert "kısmi" in note
        assert "decompile edildi" not in note

    def test_cikti_adi_fixed_sizmaz_noktali_adlar_carpismaz(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path, monkeypatch
    ):
        """'hello' -> hello.disasm.txt (hello.fixed.* DEĞİL); 'pkg.a' ile 'pkg.b' çakışmaz.

        Eski kod Path.with_suffix/stem kullanıyordu: çıktı 'hello.fixed.py' oluyor,
        'pkg.a'/'pkg.b' ikisi de 'pkg.fixed.*' adına yazılıp birbirini eziyordu.
        """
        import sys
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.packed_binary import ExtractedFile
        running = f"{sys.version_info.major}.{sys.version_info.minor}"
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)  # stdlib dis
        files = []
        for name, src in (("hello", "x = 1\n"), ("pkg.a", "A = 1\n"), ("pkg.b", "B = 2\n")):
            p = self._stripped(tmp_path, name, src)
            files.append(ExtractedFile(path=p, original_name=name, file_type="pyc",
                                       size=p.stat().st_size))
        summary = python_analyzer._decompile_pyc_files(files, tmp_path / "proj", py_version=running)

        out = sorted(p.name for p in (tmp_path / "proj" / "source").iterdir())
        assert out == ["hello.disasm.txt", "pkg.a.disasm.txt", "pkg.b.disasm.txt"]
        assert summary["disasm"] == 3

    def test_vendor_dizini_pycdas_aramasina_da_gider(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path, monkeypatch
    ):
        """vendor/pycdc hem pycdc hem pycdas çözümlemesine verilmeli (setup_pycdc.sh ikisini kurar)."""
        import sys
        import karadul.analyzers.python_binary as pb
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.packed_binary import ExtractedFile
        running = f"{sys.version_info.major}.{sys.version_info.minor}"
        vendor = str(tmp_path / "vendor")
        monkeypatch.setattr(pb, "_vendor_tool_paths", lambda: [vendor])
        calls: list = []

        def fake_resolve(name, extra_paths=None):
            calls.append((name, list(extra_paths or [])))
            return None

        monkeypatch.setattr(pd, "resolve_tool", fake_resolve)
        pyc = self._stripped(tmp_path, "m", "x = 1\n")
        files = [ExtractedFile(path=pyc, original_name="m", file_type="pyc", size=pyc.stat().st_size)]
        python_analyzer._decompile_pyc_files(files, tmp_path / "proj", py_version=running)

        assert ("pycdc", [vendor]) in calls
        assert ("pycdas", [vendor]) in calls

    def test_not_pycdc_kurulu_iken_kurun_demez(self):
        from karadul.analyzers.python_binary import _pyinstaller_note
        base = {"total_pyc": 2, "decompiled": 0, "partial": 0, "disasm": 2, "failed": 0}
        assert "pycdc kurun" in _pyinstaller_note({**base, "pycdc_available": False})
        assert "pycdc kurun" not in _pyinstaller_note({**base, "pycdc_available": True})


class TestDecompileZinciriPyzGuvenceleri:
    """PYZ entegrasyonuyla _decompile_pyc_files'a eklenen iki güvence (2026-09-25)."""

    @staticmethod
    def _pyc(path: Path, src: str) -> Path:
        import marshal
        import sys
        from karadul.analyzers.pyc_decompiler import repair_pyc_header
        running = f"{sys.version_info.major}.{sys.version_info.minor}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(repair_pyc_header(marshal.dumps(compile(src, "x.py", "exec")), running))
        return path

    def test_ayni_kok_adli_pycler_birbirini_ezmez(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path, monkeypatch
    ):
        """CArchive betiği 'app' ile PYZ modülü 'app' (ve harf farkı) ayrı çıktılara yazılır."""
        from karadul.analyzers import pyc_decompiler as pd
        from karadul.analyzers.packed_binary import ExtractedFile
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)  # stdlib dis
        a = self._pyc(tmp_path / "extracted" / "app", "A = 1\n")
        b = self._pyc(tmp_path / "extracted" / "PYZ.pyz_extracted" / "app.pyc", "B = 2\n")
        c = self._pyc(tmp_path / "extracted" / "PYZ.pyz_extracted" / "App.pyc", "C = 3\n")
        files = [ExtractedFile(path=p, original_name=p.name, file_type="pyc", size=1) for p in (a, b, c)]
        summary = python_analyzer._decompile_pyc_files(files, tmp_path / "proj")
        out = sorted(p.name for p in (tmp_path / "proj" / "source").iterdir())
        assert out == ["App~3.disasm.txt", "app.disasm.txt", "app~2.disasm.txt"]
        assert summary["disasm"] == 3

    def test_tek_dosya_yazma_hatasi_zinciri_durdurmaz(
        self, python_analyzer: PythonBinaryAnalyzer, tmp_path: Path, monkeypatch
    ):
        import karadul.analyzers.python_binary as pbin
        from karadul.analyzers.packed_binary import ExtractedFile
        from karadul.analyzers.pyc_decompiler import DecompileResult
        calls: list[str] = []

        def fake_decompile(pyc_path, out_dir, **kw):
            calls.append(kw["out_stem"])
            if kw["out_stem"] == "kotu":
                raise OSError(63, "File name too long")
            return DecompileResult(source_path=pyc_path, method="disasm", is_disassembly=True)

        monkeypatch.setattr(pbin, "decompile_pyc", fake_decompile)
        files = [
            ExtractedFile(path=self._pyc(tmp_path / n, "x = 1\n"), original_name=n,
                          file_type="pyc", size=1)
            for n in ("kotu.pyc", "iyi.pyc")
        ]
        summary = python_analyzer._decompile_pyc_files(files, tmp_path / "proj")
        assert calls == ["kotu", "iyi"]
        assert summary["failed"] == 1 and summary["disasm"] == 1
