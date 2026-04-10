"""Delphi Binary Analyzer test suite.

RTTI detection, DFM form resource extraction, VMT traversal,
compiler version tespiti testleri.

Gercek Delphi binary olmadan calismali -- mock data kullanir.
"""

from __future__ import annotations

import io
import json
import re
import struct
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.delphi_binary import (
    DelphiBinaryAnalyzer,
    _DFM_BIN_MAGIC_TPF0,
    _DFM_TEXT_MAGIC,
    _DELPHI_COMPILER_STRINGS,
    _DELPHI_VERSION_MAP,
    _KNOWN_DELPHI_CLASSES,
    _TK_CLASS,
    _TK_CLASS_V2,
    _detect_delphi_binary,
    _detect_compiler_version,
    _extract_rtti_classes,
    _extract_dfm_resources,
    _extract_vmt_info,
    _parse_dfm_binary,
)
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace


# --------------------------------------------------------------------------
# Helpers: mock Delphi binary olusturma
# --------------------------------------------------------------------------

def _build_delphi_pe(
    compiler_string: str = "Embarcadero Delphi",
    include_rtti: bool = True,
    rtti_classes: list[str] | None = None,
    include_dfm: bool = False,
    dfm_forms: list[tuple[str, str]] | None = None,
    include_mangled: bool = True,
    mangled_symbols: list[tuple[str, str, str]] | None = None,
) -> bytes:
    """Mock Delphi PE binary olustur.

    Args:
        compiler_string: Compiler version string
        include_rtti: RTTI class bilgileri ekle
        rtti_classes: RTTI class isimleri (["TMainForm", "TDataModule", ...])
        include_dfm: DFM form kaynaklari ekle
        dfm_forms: DFM form'lari [(name, class), ...]
        include_mangled: Delphi mangled symbol'ler ekle
        mangled_symbols: [(unit, class, method), ...]
    """
    buf = io.BytesIO()

    # Minimal PE header
    buf.write(b"MZ")
    buf.write(b"\x00" * 58)
    # e_lfanew -> 0x80
    buf.seek(0x3C)
    buf.write(struct.pack("<I", 0x80))
    buf.seek(0x80)
    buf.write(b"PE\x00\x00")
    buf.write(b"\x00" * 20)  # COFF header
    buf.write(b"\x00" * 128)  # Optional header stub

    # Compiler string
    buf.write(compiler_string.encode("ascii"))
    buf.write(b"\x00" * 16)

    # Delphi runtime markers
    buf.write(b"System.TObject\x00")
    buf.write(b"System.SysUtils\x00")
    buf.write(b"System.Classes.TComponent\x00")
    buf.write(b"@System@@Finalization$qqrv\x00")
    buf.write(b"@System@TObject@\x00")

    # RTTI class entries
    if include_rtti:
        classes = rtti_classes or ["TMainForm", "TDataModule", "TMyButton", "TSettingsForm"]
        for cls_name in classes:
            buf.write(b"\x00" * 4)  # padding
            buf.write(bytes([_TK_CLASS]))  # tkClass
            name_bytes = cls_name.encode("ascii")
            buf.write(bytes([len(name_bytes)]))
            buf.write(name_bytes)
            buf.write(b"\x00" * 8)  # padding after name
            # Parent class ismi (TForm icin)
            if cls_name.startswith("TMain") or cls_name.endswith("Form"):
                parent = "TForm"
                buf.write(bytes([len(parent)]))
                buf.write(parent.encode("ascii"))
            buf.write(b"\x00" * 16)

    # DFM form resources
    if include_dfm:
        forms = dfm_forms or [("MainForm", "TMainForm"), ("SettingsForm", "TSettingsForm")]
        for form_name, form_class in forms:
            buf.write(b"\x00" * 8)  # padding
            buf.write(_DFM_BIN_MAGIC_TPF0)
            cls_bytes = form_class.encode("ascii")
            buf.write(bytes([len(cls_bytes)]))
            buf.write(cls_bytes)
            name_bytes = form_name.encode("ascii")
            buf.write(bytes([len(name_bytes)]))
            buf.write(name_bytes)
            # Child component'ler
            for comp_class, comp_name in [("TButton", "btnOK"), ("TLabel", "lblTitle")]:
                c = comp_class.encode("ascii")
                n = comp_name.encode("ascii")
                buf.write(bytes([len(c)]))
                buf.write(c)
                buf.write(bytes([len(n)]))
                buf.write(n)
            buf.write(b"\x00" * 32)

    # Mangled symbols
    if include_mangled:
        symbols = mangled_symbols or [
            ("MainUnit", "TMainForm", "FormCreate"),
            ("MainUnit", "TMainForm", "FormDestroy"),
            ("MainUnit", "TMainForm", "btnClickHandler"),
            ("DataUnit", "TDataModule", "LoadData"),
            ("DataUnit", "TDataModule", "SaveData"),
            ("Utils", "THelper", "DoSomething"),
        ]
        for unit, cls, method in symbols:
            buf.write(b"\x00")
            buf.write(f"@{unit}@{cls}@{method}$qqrv".encode("ascii"))
            buf.write(b"\x00")

    # .pas referanslari
    buf.write(b"\x00MainUnit.pas\x00")
    buf.write(b"\x00DataUnit.pas\x00")
    buf.write(b"\x00Utils.pas\x00")

    # Pad
    buf.write(b"\x00" * 256)

    return buf.getvalue()


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture
def analyzer(config: Config) -> DelphiBinaryAnalyzer:
    return DelphiBinaryAnalyzer(config)


@pytest.fixture
def mock_delphi_binary(tmp_path: Path) -> Path:
    """Mock Delphi binary dosyasi."""
    data = _build_delphi_pe(
        compiler_string="Embarcadero Delphi 11",
        include_rtti=True,
        include_dfm=True,
        include_mangled=True,
    )
    pe_path = tmp_path / "DelphiApp.exe"
    pe_path.write_bytes(data)
    return pe_path


@pytest.fixture
def mock_delphi_no_rtti(tmp_path: Path) -> Path:
    """RTTI olmayan Delphi binary."""
    data = _build_delphi_pe(
        compiler_string="Borland Delphi 7",
        include_rtti=False,
        include_dfm=False,
        include_mangled=True,
    )
    pe_path = tmp_path / "OldDelphi.exe"
    pe_path.write_bytes(data)
    return pe_path


@pytest.fixture
def mock_native_pe(tmp_path: Path) -> Path:
    """Delphi olmayan native PE."""
    buf = io.BytesIO()
    buf.write(b"MZ")
    buf.write(b"\x00" * 254)
    buf.write(b"This is a C++ application")
    buf.write(b"\x00" * 256)
    pe_path = tmp_path / "NativeApp.exe"
    pe_path.write_bytes(buf.getvalue())
    return pe_path


@pytest.fixture
def mock_delphi_target(mock_delphi_binary: Path) -> TargetInfo:
    return TargetInfo(
        path=mock_delphi_binary,
        name="DelphiApp",
        target_type=TargetType.DELPHI_BINARY,
        language=Language.DELPHI,
        file_size=mock_delphi_binary.stat().st_size,
        file_hash="abc123",
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(tmp_path / "workspace", "test_delphi")
    ws.create()
    return ws


# --------------------------------------------------------------------------
# Test: Delphi detection
# --------------------------------------------------------------------------

class TestDelphiDetection:
    """Delphi binary tespit testleri."""

    def test_delphi_binary_detected(self, mock_delphi_binary: Path):
        """Delphi compiler string'li binary tespit edilmeli."""
        data = mock_delphi_binary.read_bytes()
        result = _detect_delphi_binary(data)
        assert result["is_delphi"] is True
        assert len(result["evidence"]) > 0

    def test_delphi_compiler_string(self, mock_delphi_binary: Path):
        """Compiler string dogru parse edilmeli."""
        data = mock_delphi_binary.read_bytes()
        result = _detect_delphi_binary(data)
        assert "Embarcadero" in result.get("compiler_version", "")

    def test_native_pe_not_delphi(self, mock_native_pe: Path):
        """Native PE binary Delphi olarak tespit edilmemeli."""
        data = mock_native_pe.read_bytes()
        result = _detect_delphi_binary(data)
        assert result["is_delphi"] is False

    def test_empty_data_not_delphi(self):
        """Bos veri Delphi olarak tespit edilmemeli."""
        result = _detect_delphi_binary(b"")
        assert result["is_delphi"] is False

    def test_runtime_markers_detected(self, mock_delphi_binary: Path):
        """Delphi runtime marker'lari tespit edilmeli."""
        data = mock_delphi_binary.read_bytes()
        result = _detect_delphi_binary(data)
        assert any("runtime marker" in e.lower() or "marker" in e.lower()
                    for e in result["evidence"])

    def test_mangled_symbols_detected(self, mock_delphi_binary: Path):
        """Delphi mangled symbol'ler tespit edilmeli."""
        data = mock_delphi_binary.read_bytes()
        result = _detect_delphi_binary(data)
        assert any("mangled" in e.lower() for e in result["evidence"])

    def test_rtti_detected(self, mock_delphi_binary: Path):
        """RTTI class bilgileri tespit edilmeli."""
        data = mock_delphi_binary.read_bytes()
        result = _detect_delphi_binary(data)
        assert result["rtti_found"] is True


# --------------------------------------------------------------------------
# Test: RTTI class extraction
# --------------------------------------------------------------------------

class TestRttiExtraction:
    """RTTI class extraction testleri."""

    def test_rtti_classes_found(self, mock_delphi_binary: Path):
        """RTTI class'lari cikarilmali."""
        data = mock_delphi_binary.read_bytes()
        classes = _extract_rtti_classes(data)
        assert len(classes) > 0
        names = [c["name"] for c in classes]
        assert "TMainForm" in names

    def test_rtti_class_names_valid(self, mock_delphi_binary: Path):
        """RTTI class isimleri T ile baslamali."""
        data = mock_delphi_binary.read_bytes()
        classes = _extract_rtti_classes(data)
        for cls in classes:
            assert cls["name"].startswith("T"), f"Invalid class name: {cls['name']}"

    def test_rtti_parent_detection(self, mock_delphi_binary: Path):
        """Parent class tespiti calismali."""
        data = mock_delphi_binary.read_bytes()
        classes = _extract_rtti_classes(data)
        forms = [c for c in classes if "Form" in c["name"]]
        # En az bir form'un parent'i TForm olmali
        has_parent = any(c.get("parent") == "TForm" for c in forms)
        assert has_parent, "TForm parent tespit edilemedi"

    def test_rtti_vcl_flag(self, mock_delphi_binary: Path):
        """Bilinen VCL class'lari is_vcl=True olmali."""
        data = mock_delphi_binary.read_bytes()
        classes = _extract_rtti_classes(data)
        # TMainForm bilinen VCL degil ama TForm bilinen
        # Mock'umuzda TMainForm var, bu VCL degil
        main_form = [c for c in classes if c["name"] == "TMainForm"]
        assert len(main_form) > 0
        # TMainForm _KNOWN_DELPHI_CLASSES icinde degil
        assert main_form[0]["is_vcl"] is False

    def test_no_rtti_in_clean_data(self):
        """RTTI olmayan veride bos liste donmeli."""
        data = b"\x00" * 1000 + b"just plain text" + b"\x00" * 1000
        classes = _extract_rtti_classes(data)
        assert len(classes) == 0

    def test_rtti_max_classes_limit(self):
        """max_classes limiti calismali."""
        # Cok fazla RTTI entry olustur
        buf = io.BytesIO()
        for i in range(20):
            buf.write(b"\x00" * 4)
            buf.write(bytes([_TK_CLASS]))
            name = f"TClass{i:03d}"
            buf.write(bytes([len(name)]))
            buf.write(name.encode("ascii"))
            buf.write(b"\x00" * 16)

        data = buf.getvalue()
        classes = _extract_rtti_classes(data, max_classes=5)
        assert len(classes) <= 5


# --------------------------------------------------------------------------
# Test: DFM form extraction
# --------------------------------------------------------------------------

class TestDfmExtraction:
    """DFM form resource extraction testleri."""

    def test_binary_dfm_found(self, mock_delphi_binary: Path):
        """Binary DFM (TPF0) kaynaklari cikarilmali."""
        data = mock_delphi_binary.read_bytes()
        forms = _extract_dfm_resources(data)
        assert len(forms) > 0

    def test_dfm_form_name(self, mock_delphi_binary: Path):
        """DFM form ismi dogru cikarilmali."""
        data = mock_delphi_binary.read_bytes()
        forms = _extract_dfm_resources(data)
        form_names = [f["form_name"] for f in forms]
        assert "MainForm" in form_names

    def test_dfm_form_class(self, mock_delphi_binary: Path):
        """DFM form class'i dogru cikarilmali."""
        data = mock_delphi_binary.read_bytes()
        forms = _extract_dfm_resources(data)
        main_forms = [f for f in forms if f["form_name"] == "MainForm"]
        assert len(main_forms) > 0
        assert main_forms[0]["form_class"] == "TMainForm"

    def test_dfm_components(self, mock_delphi_binary: Path):
        """DFM icindeki child component'ler cikarilmali."""
        data = mock_delphi_binary.read_bytes()
        forms = _extract_dfm_resources(data)
        # En az bir form'da component olmali
        has_components = any(len(f.get("components", [])) > 0 for f in forms)
        assert has_components, "DFM component'leri tespit edilemedi"

    def test_text_dfm_detection(self):
        """Text formatindaki DFM tespit edilmeli."""
        data = b"\x00" * 32 + b"object Form1: TForm1\n  Left = 0\n  Top = 0\nend\n" + b"\x00" * 32
        forms = _extract_dfm_resources(data)
        assert len(forms) >= 1
        assert forms[0]["form_name"] == "Form1"
        assert forms[0]["form_class"] == "TForm1"
        assert forms[0]["format"] == "text"

    def test_no_dfm_in_clean_data(self):
        """DFM olmayan veride bos liste donmeli."""
        data = b"\x00" * 500 + b"no forms here" + b"\x00" * 500
        forms = _extract_dfm_resources(data)
        assert len(forms) == 0

    def test_parse_dfm_binary_tpf0(self):
        """TPF0 binary DFM parse edilmeli."""
        buf = io.BytesIO()
        buf.write(_DFM_BIN_MAGIC_TPF0)
        # Class name
        cls = b"TMyForm"
        buf.write(bytes([len(cls)]))
        buf.write(cls)
        # Component name
        name = b"MyForm"
        buf.write(bytes([len(name)]))
        buf.write(name)
        buf.write(b"\x00" * 32)

        result = _parse_dfm_binary(buf.getvalue(), 0)
        assert result is not None
        assert result["form_class"] == "TMyForm"
        assert result["form_name"] == "MyForm"

    def test_parse_dfm_binary_invalid(self):
        """Gecersiz DFM verisi None donmeli."""
        result = _parse_dfm_binary(b"TPF0\x00", 0)
        assert result is None


# --------------------------------------------------------------------------
# Test: VMT traversal
# --------------------------------------------------------------------------

class TestVmtTraversal:
    """Virtual Method Table traversal testleri."""

    def test_mangled_symbols_extracted(self, mock_delphi_binary: Path):
        """Mangled symbol'ler cikarilmali."""
        data = mock_delphi_binary.read_bytes()
        vmt = _extract_vmt_info(data)
        assert len(vmt["mangled_symbols"]) > 0

    def test_class_method_grouping(self, mock_delphi_binary: Path):
        """Method'lar class bazinda gruplanmali."""
        data = mock_delphi_binary.read_bytes()
        vmt = _extract_vmt_info(data)

        # MainUnit.TMainForm olmali
        main_entries = [s for s in vmt["mangled_symbols"] if s["class"] == "TMainForm"]
        assert len(main_entries) > 0
        assert "FormCreate" in main_entries[0]["methods"]

    def test_virtual_method_count(self, mock_delphi_binary: Path):
        """Virtual method sayisi > 0 olmali."""
        data = mock_delphi_binary.read_bytes()
        vmt = _extract_vmt_info(data)
        assert vmt["virtual_method_count"] > 0

    def test_class_hierarchy(self, mock_delphi_binary: Path):
        """Class hiyerarsisi cikarilmali."""
        data = mock_delphi_binary.read_bytes()
        vmt = _extract_vmt_info(data)
        assert len(vmt["class_hierarchy"]) > 0
        assert all(c.startswith("T") for c in vmt["class_hierarchy"])

    def test_no_vmt_in_clean_data(self):
        """Mangled symbol olmayan veride bos sonuc donmeli."""
        data = b"no delphi symbols here" * 100
        vmt = _extract_vmt_info(data)
        assert len(vmt["mangled_symbols"]) == 0


# --------------------------------------------------------------------------
# Test: Compiler version detection
# --------------------------------------------------------------------------

class TestCompilerVersion:
    """Compiler version tespit testleri."""

    def test_embarcadero_detected(self, mock_delphi_binary: Path):
        """Embarcadero Delphi 11 string'i tespit edilmeli."""
        data = mock_delphi_binary.read_bytes()
        result = _detect_compiler_version(data)
        assert result["version_string"] is not None
        assert "Embarcadero" in result["version_string"]

    def test_borland_detected(self, mock_delphi_no_rtti: Path):
        """Borland Delphi 7 string'i tespit edilmeli."""
        data = mock_delphi_no_rtti.read_bytes()
        result = _detect_compiler_version(data)
        assert result["version_string"] is not None
        assert "Borland" in result["version_string"]

    def test_version_label(self, mock_delphi_binary: Path):
        """Version label dogru eslesmeli."""
        data = mock_delphi_binary.read_bytes()
        result = _detect_compiler_version(data)
        if result["version_label"]:
            assert "Alexandria" in result["version_label"] or "Delphi" in result["version_label"]

    def test_no_compiler_in_native(self, mock_native_pe: Path):
        """Native PE'de Delphi compiler string olmamali."""
        data = mock_native_pe.read_bytes()
        result = _detect_compiler_version(data)
        assert result["version_string"] is None

    def test_linker_version(self, mock_delphi_binary: Path):
        """PE linker version parse edilebilmeli."""
        data = mock_delphi_binary.read_bytes()
        result = _detect_compiler_version(data)
        # Linker version parse edilememis olabilir (mock PE basitlestirilmis)
        # Ama fonksiyon hata vermemeli
        assert isinstance(result.get("linker_version"), (str, type(None)))


# --------------------------------------------------------------------------
# Test: can_handle
# --------------------------------------------------------------------------

class TestCanHandle:
    """DelphiBinaryAnalyzer.can_handle testleri."""

    def test_delphi_exe_detected(self, analyzer: DelphiBinaryAnalyzer, mock_delphi_binary: Path):
        """Delphi .exe tespit edilmeli."""
        target = TargetInfo(
            path=mock_delphi_binary, name="DelphiApp",
            target_type=TargetType.DELPHI_BINARY, language=Language.DELPHI,
            file_size=100, file_hash="x",
        )
        assert analyzer.can_handle(target) is True

    def test_native_pe_rejected(self, analyzer: DelphiBinaryAnalyzer, mock_native_pe: Path):
        """Native PE reddedilmeli."""
        target = TargetInfo(
            path=mock_native_pe, name="NativeApp",
            target_type=TargetType.PE_BINARY, language=Language.UNKNOWN,
            file_size=100, file_hash="x",
        )
        assert analyzer.can_handle(target) is False

    def test_non_pe_extension_rejected(self, analyzer: DelphiBinaryAnalyzer, tmp_path: Path):
        """.txt uzantili dosya reddedilmeli."""
        f = tmp_path / "test.txt"
        f.write_bytes(b"MZ" + b"Embarcadero Delphi" + b"\x00" * 100)
        target = TargetInfo(
            path=f, name="test",
            target_type=TargetType.UNKNOWN, language=Language.UNKNOWN,
            file_size=100, file_hash="x",
        )
        assert analyzer.can_handle(target) is False

    def test_bpl_extension_accepted(self, analyzer: DelphiBinaryAnalyzer, tmp_path: Path):
        """.bpl uzantili Delphi package dosyasi."""
        data = _build_delphi_pe(compiler_string="Embarcadero Delphi")
        f = tmp_path / "mypackage.bpl"
        f.write_bytes(data)
        target = TargetInfo(
            path=f, name="mypackage",
            target_type=TargetType.DELPHI_BINARY, language=Language.DELPHI,
            file_size=len(data), file_hash="x",
        )
        assert analyzer.can_handle(target) is True


# --------------------------------------------------------------------------
# Test: Full analyze_static pipeline
# --------------------------------------------------------------------------

class TestAnalyzeStatic:
    """analyze_static integration testleri."""

    def test_produces_stage_result(
        self, analyzer: DelphiBinaryAnalyzer, mock_delphi_target: TargetInfo, workspace: Workspace,
    ):
        """Analiz StageResult dondurmeli."""
        result = analyzer.analyze_static(mock_delphi_target, workspace)
        assert isinstance(result, StageResult)
        assert result.success is True
        assert result.stage_name == "static"
        assert result.duration_seconds >= 0

    def test_stats_populated(
        self, analyzer: DelphiBinaryAnalyzer, mock_delphi_target: TargetInfo, workspace: Workspace,
    ):
        """Istatistikler doldurulmali."""
        result = analyzer.analyze_static(mock_delphi_target, workspace)
        assert result.stats["rtti_classes"] > 0
        assert result.stats["dfm_forms"] > 0
        assert result.stats["mangled_symbols"] > 0
        assert result.stats["compiler_version"] is not None

    def test_analysis_json_written(
        self, analyzer: DelphiBinaryAnalyzer, mock_delphi_target: TargetInfo, workspace: Workspace,
    ):
        """Analiz sonucu JSON'a yazilmali."""
        result = analyzer.analyze_static(mock_delphi_target, workspace)
        path = Path(result.artifacts["delphi_analysis"])
        assert path.exists()
        data = json.loads(path.read_text())
        assert "detection" in data
        assert "rtti_classes" in data
        assert "dfm_forms" in data
        assert "vmt_info" in data
        assert "compiler" in data

    def test_units_detected(
        self, analyzer: DelphiBinaryAnalyzer, mock_delphi_target: TargetInfo, workspace: Workspace,
    ):
        """Unit isimleri cikarilmali."""
        result = analyzer.analyze_static(mock_delphi_target, workspace)
        path = Path(result.artifacts["delphi_analysis"])
        data = json.loads(path.read_text())
        units = data.get("units", [])
        assert len(units) > 0


# --------------------------------------------------------------------------
# Test: reconstruct
# --------------------------------------------------------------------------

class TestReconstruct:
    """Delphi proje reconstruction testleri."""

    def test_dpr_generated(
        self, analyzer: DelphiBinaryAnalyzer, mock_delphi_target: TargetInfo, workspace: Workspace,
    ):
        """Reconstruction .dpr dosyasi olusturmali."""
        analyzer.analyze_static(mock_delphi_target, workspace)
        result = analyzer.reconstruct(mock_delphi_target, workspace)
        assert result is not None
        assert result.success is True

        project_dir = Path(result.artifacts["delphi_project"])
        dpr_files = list(project_dir.glob("*.dpr"))
        assert len(dpr_files) == 1

    def test_dpr_content(self, analyzer: DelphiBinaryAnalyzer):
        """DPR icerigi dogru olmali."""
        analysis = {
            "units": ["MainUnit", "DataUnit"],
            "dfm_forms": [{"form_name": "MainForm", "form_class": "TMainForm"}],
            "compiler": {"version_label": "Delphi 11 Alexandria"},
        }
        content = analyzer._generate_dpr("TestApp", analysis)
        assert "program TestApp" in content
        assert "Karadul" in content
        assert "Delphi 11" in content

    def test_form_pas_generated(
        self, analyzer: DelphiBinaryAnalyzer, mock_delphi_target: TargetInfo, workspace: Workspace,
    ):
        """DFM form'lari icin .pas stub dosyalari olusturulmali."""
        analyzer.analyze_static(mock_delphi_target, workspace)
        result = analyzer.reconstruct(mock_delphi_target, workspace)
        assert result is not None

        project_dir = Path(result.artifacts["delphi_project"])
        pas_files = list(project_dir.glob("*.pas"))
        assert len(pas_files) > 0

    def test_form_unit_content(self, analyzer: DelphiBinaryAnalyzer):
        """Form unit icerigi dogru olmali."""
        form_data = {
            "form_name": "MainForm",
            "form_class": "TMainForm",
            "components": ["btnOK: TButton", "lblTitle: TLabel"],
        }
        content = analyzer._generate_form_unit("MainForm", "TMainForm", form_data)
        assert "unit MainForm" in content
        assert "TMainForm = class(TForm)" in content
        assert "btnOK: TButton;" in content


# --------------------------------------------------------------------------
# Test: deobfuscate
# --------------------------------------------------------------------------

class TestDeobfuscate:
    """Deobfuscation placeholder testleri."""

    def test_returns_success(
        self, analyzer: DelphiBinaryAnalyzer, mock_delphi_target: TargetInfo, workspace: Workspace,
    ):
        """Deobfuscate her zaman success donmeli."""
        result = analyzer.deobfuscate(mock_delphi_target, workspace)
        assert result.success is True
        assert result.stage_name == "deobfuscate"


# --------------------------------------------------------------------------
# Test: Known Delphi classes
# --------------------------------------------------------------------------

class TestKnownClasses:
    """Bilinen Delphi VCL/FMX class kontrolleri."""

    def test_tform_in_known(self):
        assert "TForm" in _KNOWN_DELPHI_CLASSES

    def test_tbutton_in_known(self):
        assert "TButton" in _KNOWN_DELPHI_CLASSES

    def test_tapplication_in_known(self):
        assert "TApplication" in _KNOWN_DELPHI_CLASSES

    def test_tthread_in_known(self):
        assert "TThread" in _KNOWN_DELPHI_CLASSES

    def test_custom_class_not_known(self):
        assert "TMyCustomClass" not in _KNOWN_DELPHI_CLASSES
