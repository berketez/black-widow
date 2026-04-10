"""Swift binary analyzer testleri.

Mock data ile Swift sembol tespiti, demangling ve
metadata extraction testleri.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.swift_binary import (
    SwiftBinaryAnalyzer,
    _OBJC_CLASS_REF,
    _OBJC_METACLASS_REF,
    _PROTOCOL_CONFORMANCE_MANGLED,
    _PROTOCOL_WITNESS,
    _SWIFT_MANGLED_PREFIX,
    _TYPE_METADATA,
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
def analyzer(config: Config) -> SwiftBinaryAnalyzer:
    """SwiftBinaryAnalyzer instance."""
    return SwiftBinaryAnalyzer(config)


@pytest.fixture
def swift_binary_content() -> bytes:
    """Swift binary'yi temsil eden mock icerik.

    Mach-O 64-bit header + Swift runtime string'leri.
    """
    # MH_MAGIC_64 = 0xFEEDFACF (big-endian icin pack)
    magic = struct.pack(">I", 0xFEEDFACF)
    padding = b"\x00" * 60  # Header padding

    # Swift runtime referanslari
    swift_content = (
        b"\x00_swift_allocObject\x00"
        b"\x00_swift_release\x00"
        b"\x00_swift_retain\x00"
        b"\x00swift_getObjectType\x00"
        b"\x00libswiftCore\x00"
        b"\x00libswiftFoundation\x00"
        b"\x00Swift.String\x00"
        b"\x00Swift.Int\x00"
        b"\x00Swift.Array\x00"
        b"\x00_OBJC_CLASS_$_MyViewController\x00"
        b"\x00_OBJC_CLASS_$_AppDelegate\x00"
        b"\x00_OBJC_METACLASS_$_MyViewController\x00"
        b"\x00$s12MyApp0B7ModuleC10fetchData4ySSSgAA0E5ModelCSg_tF\x00"
        b"\x00$s12MyApp0B7ModuleV\x00"
        b"\x00$s12MyApp8ProtocolMa\x00"
        b"\x00$s12MyApp8NetworkP_WP\x00"
        b"\x00protocol witness for Network.fetch in conformance MyModule\x00"
        b"\x00type metadata accessor for MyApp.DataModel\x00"
        b"\x00nominal type descriptor for MyApp.AppState\x00"
        b"\x00@objc MyViewController.viewDidLoad()\x00"
        b"\x00enum case for MyApp.Status\x00"
    )

    return magic + padding + swift_content


@pytest.fixture
def swift_binary_file(tmp_path: Path, swift_binary_content: bytes) -> Path:
    """Gecici dizinde Swift binary olustur."""
    bin_file = tmp_path / "SwiftApp"
    bin_file.write_bytes(swift_binary_content)
    return bin_file


@pytest.fixture
def swift_target_info(swift_binary_file: Path) -> TargetInfo:
    """Swift binary icin TargetInfo."""
    return TargetInfo(
        path=swift_binary_file,
        name="SwiftApp",
        target_type=TargetType.MACHO_BINARY,
        language=Language.SWIFT,
        file_size=swift_binary_file.stat().st_size,
        file_hash="mock_hash_abc123",
    )


@pytest.fixture
def non_swift_binary_content() -> bytes:
    """Swift OLMAYAN binary icerik (sadece C++)."""
    magic = struct.pack(">I", 0xFEEDFACF)
    padding = b"\x00" * 60
    content = (
        b"\x00__cxa_throw\x00"
        b"\x00std::string\x00"
        b"\x00__gnu_cxx\x00"
    )
    return magic + padding + content


@pytest.fixture
def non_swift_binary_file(tmp_path: Path, non_swift_binary_content: bytes) -> Path:
    """C++ binary dosyasi."""
    bin_file = tmp_path / "CppApp"
    bin_file.write_bytes(non_swift_binary_content)
    return bin_file


@pytest.fixture
def non_swift_target_info(non_swift_binary_file: Path) -> TargetInfo:
    """C++ binary icin TargetInfo."""
    return TargetInfo(
        path=non_swift_binary_file,
        name="CppApp",
        target_type=TargetType.MACHO_BINARY,
        language=Language.CPP,
        file_size=non_swift_binary_file.stat().st_size,
        file_hash="mock_hash_cpp",
    )


# --------------------------------------------------------------------------
# Regex pattern testleri
# --------------------------------------------------------------------------

class TestSwiftRegexPatterns:
    """Swift sembol regex pattern'lerinin dogrulugu."""

    def test_swift_mangled_prefix_matches(self):
        """$s prefix'li mangled semboller eslesmeli."""
        assert _SWIFT_MANGLED_PREFIX.search("$s12MyApp0B7ModuleC10fetchData4ySSSg")
        assert _SWIFT_MANGLED_PREFIX.search("_$s12MyApp0B7ModuleV")
        assert _SWIFT_MANGLED_PREFIX.search("$S5Hello4mainyyF")

    def test_swift_mangled_prefix_no_false_positive(self):
        """$s olmayan string'ler eslesmemeli."""
        assert not _SWIFT_MANGLED_PREFIX.search("runtime.gopanic")
        assert not _SWIFT_MANGLED_PREFIX.search("__cxa_throw")

    def test_objc_class_ref_pattern(self):
        """_OBJC_CLASS_$_ pattern'i eslesmeli."""
        match = _OBJC_CLASS_REF.search("_OBJC_CLASS_$_MyViewController")
        assert match is not None
        assert match.group(1) == "MyViewController"

    def test_objc_metaclass_ref_pattern(self):
        """_OBJC_METACLASS_$_ pattern'i eslesmeli."""
        match = _OBJC_METACLASS_REF.search("_OBJC_METACLASS_$_AppDelegate")
        assert match is not None
        assert match.group(1) == "AppDelegate"

    def test_protocol_witness_pattern(self):
        """Protocol witness pattern eslesmeli."""
        text = "protocol witness for Network.fetch in conformance MyModule"
        match = _PROTOCOL_WITNESS.search(text)
        assert match is not None
        assert match.group(1) == "Network.fetch"
        assert match.group(2) == "MyModule"

    def test_protocol_conformance_mangled(self):
        """$s...WP mangled conformance eslesmeli."""
        assert _PROTOCOL_CONFORMANCE_MANGLED.search("$s12MyApp8NetworkP_WP")

    def test_type_metadata_pattern(self):
        """Type metadata pattern eslesmeli."""
        match = _TYPE_METADATA.search("type metadata accessor for MyApp.DataModel")
        assert match is not None
        assert match.group(1) == "MyApp.DataModel"

        match2 = _TYPE_METADATA.search("type metadata for Swift.String")
        assert match2 is not None
        assert match2.group(1) == "Swift.String"


# --------------------------------------------------------------------------
# can_handle testleri
# --------------------------------------------------------------------------

class TestCanHandle:
    """SwiftBinaryAnalyzer.can_handle tespiti."""

    def test_swift_language_shortcut(self, swift_target_info: TargetInfo):
        """Language.SWIFT olan target dogrudan True donmeli."""
        assert SwiftBinaryAnalyzer.can_handle(swift_target_info) is True

    def test_swift_binary_detected_by_signatures(
        self, swift_binary_file: Path,
    ):
        """Swift runtime string'leri ile tespit."""
        target = TargetInfo(
            path=swift_binary_file,
            name="SwiftApp",
            target_type=TargetType.MACHO_BINARY,
            language=Language.UNKNOWN,  # SWIFT degil, tespit etmeli
            file_size=swift_binary_file.stat().st_size,
            file_hash="mock",
        )
        assert SwiftBinaryAnalyzer.can_handle(target) is True

    def test_non_swift_binary_rejected(self, non_swift_target_info: TargetInfo):
        """C++ binary Swift olarak tespit edilmemeli."""
        assert SwiftBinaryAnalyzer.can_handle(non_swift_target_info) is False

    def test_non_macho_rejected(self, tmp_path: Path):
        """JS bundle gibi MACHO olmayan tip reddedilmeli."""
        js_file = tmp_path / "bundle.js"
        js_file.write_text("console.log('hello')")
        target = TargetInfo(
            path=js_file,
            name="bundle",
            target_type=TargetType.JS_BUNDLE,
            language=Language.JAVASCRIPT,
            file_size=js_file.stat().st_size,
            file_hash="mock",
        )
        assert SwiftBinaryAnalyzer.can_handle(target) is False

    def test_nonexistent_file(self, tmp_path: Path):
        """Olmayan dosya icin False donmeli, exception atmamal."""
        target = TargetInfo(
            path=tmp_path / "nonexistent",
            name="ghost",
            target_type=TargetType.MACHO_BINARY,
            language=Language.UNKNOWN,
            file_size=0,
            file_hash="",
        )
        assert SwiftBinaryAnalyzer.can_handle(target) is False


# --------------------------------------------------------------------------
# Demangle testleri
# --------------------------------------------------------------------------

class TestDemangle:
    """Swift sembol demangling."""

    def test_regex_fallback_detects_kinds(self, analyzer: SwiftBinaryAnalyzer):
        """Regex fallback ile mangled sembol tiplerini tespit et."""
        mangled = [
            "$s12MyApp8NetworkP_WP",       # protocol_witness
            "$s12MyApp9DataModelCMa",       # type_metadata_accessor
            "$s12MyApp8StatusON",           # nominal_type_descriptor
            "$s12MyApp0B7ModuleV5value",    # struct (V)
            "$s12MyApp0B7ModuleC10fetchData", # class_or_method (C)
        ]
        result = analyzer._demangle_with_regex(mangled, [])

        assert result["total"] == 5
        assert result["method"] == "regex_fallback"
        assert result["demangled_count"] > 0

        # En az bazi tiplerin tespit edildigini dogrula
        kinds = [s.get("kind") for s in result["symbols"] if s.get("kind")]
        assert "protocol_witness" in kinds
        assert "type_metadata_accessor" in kinds

    def test_regex_fallback_unknown_symbol(self, analyzer: SwiftBinaryAnalyzer):
        """Taninmayan suffix -> unknown."""
        result = analyzer._demangle_with_regex(["$s12MyAppXYZ"], [])
        assert result["symbols"][0].get("kind", "unknown") == "unknown"


# --------------------------------------------------------------------------
# ObjC interop testleri
# --------------------------------------------------------------------------

class TestObjCInterop:
    """ObjC interop metadata extraction."""

    def test_objc_classes_from_nm(self, analyzer: SwiftBinaryAnalyzer):
        """nm ciktisindaki _OBJC_CLASS_$_ referanslarini bul."""
        nm_output = (
            "0000000100001234 S _OBJC_CLASS_$_MyViewController\n"
            "0000000100001240 S _OBJC_CLASS_$_AppDelegate\n"
            "0000000100001250 S _OBJC_METACLASS_$_MyViewController\n"
        )

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.stdout = nm_output

        with patch.object(analyzer.runner, "run_command", return_value=mock_result):
            with patch.object(analyzer.runner, "run_strings", return_value=[]):
                result = analyzer._extract_objc_interop(Path("/fake/binary"))

        assert result is not None
        assert "MyViewController" in result["classes"]
        assert "AppDelegate" in result["classes"]
        assert "MyViewController" in result["metaclasses"]
        assert result["total_classes"] == 2

    def test_objc_classes_from_strings_fallback(self, analyzer: SwiftBinaryAnalyzer):
        """nm basarisiz olursa strings fallback calismali."""
        mock_fail = MagicMock()
        mock_fail.success = False
        mock_fail.stdout = ""

        string_list = [
            "_OBJC_CLASS_$_UIViewController",
            "_OBJC_CLASS_$_NetworkManager",
            "some random string",
        ]

        with patch.object(analyzer.runner, "run_command", return_value=mock_fail):
            with patch.object(analyzer.runner, "run_strings", return_value=string_list):
                result = analyzer._extract_objc_interop(Path("/fake/binary"))

        assert result is not None
        assert "UIViewController" in result["classes"]
        assert "NetworkManager" in result["classes"]

    def test_no_objc_returns_none(self, analyzer: SwiftBinaryAnalyzer):
        """ObjC referansi yoksa None donmeli."""
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.stdout = "0000000100001234 T _main\n"

        with patch.object(analyzer.runner, "run_command", return_value=mock_result):
            with patch.object(analyzer.runner, "run_strings", return_value=[]):
                result = analyzer._extract_objc_interop(Path("/fake/binary"))

        assert result is None


# --------------------------------------------------------------------------
# Protocol extraction testleri
# --------------------------------------------------------------------------

class TestProtocolExtraction:
    """Swift protocol witness table extraction."""

    def test_protocol_witness_from_strings(self, analyzer: SwiftBinaryAnalyzer):
        """strings'ten protocol witness pattern'i bul."""
        analyzer._swift_demangle_available = False  # xcrun yok

        mock_fail = MagicMock()
        mock_fail.success = False
        mock_fail.stdout = ""

        string_list = [
            "protocol witness for Network.fetch in conformance MyModule",
            "protocol witness for Codable.encode in conformance DataModel",
            "random string",
        ]

        with patch.object(analyzer.runner, "run_command", return_value=mock_fail):
            with patch.object(analyzer.runner, "run_strings", return_value=string_list):
                result = analyzer._extract_protocols(Path("/fake/binary"))

        assert result is not None
        assert len(result["witnesses"]) == 2
        assert result["witnesses"][0]["protocol_method"] == "Network.fetch"
        assert result["witnesses"][0]["conformance"] == "MyModule"

    def test_mangled_conformance_count(self, analyzer: SwiftBinaryAnalyzer):
        """$s...WP mangled conformance sayimini dogru yap."""
        analyzer._swift_demangle_available = False

        nm_output = (
            "0000000100001234 s $s12MyApp8NetworkP_WP\n"
            "0000000100001240 s $s12MyApp8CodableP_WP\n"
        )
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.stdout = nm_output

        with patch.object(analyzer.runner, "run_command", return_value=mock_result):
            with patch.object(analyzer.runner, "run_strings", return_value=[]):
                result = analyzer._extract_protocols(Path("/fake/binary"))

        assert result is not None
        assert result["mangled_conformance_count"] == 2


# --------------------------------------------------------------------------
# Type metadata testleri
# --------------------------------------------------------------------------

class TestTypeMetadata:
    """Swift type metadata extraction."""

    def test_type_metadata_from_strings(self, analyzer: SwiftBinaryAnalyzer):
        """strings'ten type metadata pattern'i bul."""
        analyzer._swift_demangle_available = False

        string_list = [
            "type metadata accessor for MyApp.DataModel",
            "type metadata for Swift.String",
            "nominal type descriptor for MyApp.AppState",
            "enum case for MyApp.Status",
            "random string",
        ]

        with patch.object(analyzer.runner, "run_strings", return_value=string_list):
            result = analyzer._extract_type_metadata(Path("/fake/binary"))

        assert result is not None
        assert result["total_types"] >= 2
        assert result["total_nominal_descriptors"] >= 1
        assert result["total_enum_cases"] >= 1

        type_names = [t["name"] for t in result["types"]]
        assert "MyApp.DataModel" in type_names
        assert "MyApp.AppState" in result["nominal_descriptors"]
        assert "MyApp.Status" in result["enum_cases"]


# --------------------------------------------------------------------------
# String filtering testleri
# --------------------------------------------------------------------------

class TestStringFiltering:
    """Swift-relevant string filtreleme."""

    def test_swift_strings_filtered(self, analyzer: SwiftBinaryAnalyzer):
        """Swift keyword'leri iceren string'ler filtrelenmeli."""
        strings = [
            "Swift.String",
            "_swift_allocObject",
            "$s12MyAppModule",
            "@objc viewDidLoad",
            "some random text",
            "abc",  # too short (< 4)
            "",
            "NSObject subclass",
            "UIKit framework",
            "type metadata for Foo",
        ]
        result = analyzer._filter_swift_strings(strings)

        assert "Swift.String" in result
        assert "_swift_allocObject" in result
        assert "$s12MyAppModule" in result
        assert "@objc viewDidLoad" in result
        assert "UIKit framework" in result
        assert "type metadata for Foo" in result
        # Bu ikisi filtrelenmemeli
        assert "some random text" not in result
        assert "abc" not in result
        assert "" not in result


# --------------------------------------------------------------------------
# analyze_static integration test (mock subprocess)
# --------------------------------------------------------------------------

class TestAnalyzeStatic:
    """analyze_static entegrasyon testi (mock subprocess ile)."""

    def test_analyze_static_produces_results(
        self,
        analyzer: SwiftBinaryAnalyzer,
        swift_target_info: TargetInfo,
        tmp_path: Path,
    ):
        """analyze_static StageResult dondurmeli, hata atmamal."""
        workspace = Workspace(tmp_path / "ws", "SwiftApp")
        workspace.create()

        # nm mock: Swift mangled semboller
        nm_mock = MagicMock()
        nm_mock.success = True
        nm_mock.stdout = (
            "0000000100001000 T _$s12MyApp0B7ModuleC10fetchDataySSSg\n"
            "0000000100001010 T _$s12MyApp8DataModelV\n"
            "0000000100001020 S _OBJC_CLASS_$_MyViewController\n"
            "0000000100001030 S _OBJC_METACLASS_$_MyViewController\n"
            "0000000100001040 s _$s12MyApp8NetworkP_WP\n"
        )
        nm_mock.stderr = ""

        # strings mock
        mock_strings = [
            "_swift_allocObject",
            "Swift.String",
            "$s12MyApp0B7ModuleC10fetchDataySSSg",
            "_OBJC_CLASS_$_MyViewController",
            "protocol witness for Network.fetch in conformance MyModule",
            "type metadata accessor for MyApp.DataModel",
            "nominal type descriptor for MyApp.AppState",
            "@objc MyViewController.viewDidLoad()",
        ]

        # swift-demangle: mevcut degil (regex fallback)
        demangle_mock = MagicMock()
        demangle_mock.success = False

        def mock_run_command(cmd, timeout=None):
            cmd_str = " ".join(str(c) for c in cmd)
            if "swift-demangle" in cmd_str:
                return demangle_mock
            return nm_mock

        with patch.object(analyzer.runner, "run_command", side_effect=mock_run_command):
            with patch.object(analyzer.runner, "run_strings", return_value=mock_strings):
                result = analyzer.analyze_static(swift_target_info, workspace)

        assert isinstance(result, StageResult)
        assert result.stage_name == "static"
        assert result.success is True
        assert result.stats.get("analyzer") == "swift_binary"
        assert result.stats.get("swift_symbol_count", 0) > 0

    def test_analyze_static_empty_binary(
        self,
        analyzer: SwiftBinaryAnalyzer,
        tmp_path: Path,
    ):
        """Bos binary icin graceful failure."""
        empty_file = tmp_path / "empty"
        empty_file.write_bytes(b"\x00" * 64)

        target = TargetInfo(
            path=empty_file,
            name="empty",
            target_type=TargetType.MACHO_BINARY,
            language=Language.SWIFT,
            file_size=64,
            file_hash="mock",
        )

        workspace = Workspace(tmp_path / "ws", "empty")
        workspace.create()

        nm_mock = MagicMock()
        nm_mock.success = False
        nm_mock.stdout = ""
        nm_mock.stderr = ""

        with patch.object(analyzer.runner, "run_command", return_value=nm_mock):
            with patch.object(analyzer.runner, "run_strings", return_value=[]):
                result = analyzer.analyze_static(target, workspace)

        assert isinstance(result, StageResult)
        # Bos binary'de raw_binary artifact var, success true olabilir
        assert result.stage_name == "static"


# --------------------------------------------------------------------------
# deobfuscate testleri
# --------------------------------------------------------------------------

class TestDeobfuscate:
    """deobfuscate stage testleri."""

    def test_deobfuscate_copies_artifacts(
        self,
        analyzer: SwiftBinaryAnalyzer,
        swift_target_info: TargetInfo,
        tmp_path: Path,
    ):
        """deobfuscate statik analiz ciktisini kopyalamali."""
        workspace = Workspace(tmp_path / "ws", "SwiftApp")
        workspace.create()

        # Statik analiz ciktisi simule et
        swift_syms = {"symbols": [{"mangled": "$s12Test"}], "method": "regex"}
        workspace.save_json("static", "swift_symbols", swift_syms)
        workspace.save_json("static", "objc_interop", {"classes": ["Foo"]})
        workspace.save_json("static", "swift_protocols", {"witnesses": []})
        workspace.save_json("static", "swift_types", {"types": []})

        result = analyzer.deobfuscate(swift_target_info, workspace)

        assert isinstance(result, StageResult)
        assert result.stage_name == "deobfuscate"
        assert result.success is True
        assert "swift_symbols_resolved" in result.artifacts

    def test_deobfuscate_missing_static(
        self,
        analyzer: SwiftBinaryAnalyzer,
        swift_target_info: TargetInfo,
        tmp_path: Path,
    ):
        """Statik analiz ciktisi yoksa hata mesaji olmal, crash olmamal."""
        workspace = Workspace(tmp_path / "ws", "SwiftApp")
        workspace.create()

        result = analyzer.deobfuscate(swift_target_info, workspace)

        assert isinstance(result, StageResult)
        assert result.stage_name == "deobfuscate"
        assert len(result.errors) > 0


# --------------------------------------------------------------------------
# Registry testleri (MACHO_BINARY override kontrolu)
# --------------------------------------------------------------------------

class TestRegistryIntegrity:
    """Swift analyzer'in mevcut registry'yi bozmadigini dogrula."""

    def test_macho_analyzer_still_registered(self):
        """MachOAnalyzer hala MACHO_BINARY icin kayitli olmal."""
        from karadul.analyzers import get_analyzer
        from karadul.analyzers.macho import MachOAnalyzer

        analyzer_cls = get_analyzer(TargetType.MACHO_BINARY)
        assert analyzer_cls is MachOAnalyzer

    def test_swift_analyzer_not_in_registry(self):
        """SwiftBinaryAnalyzer registry'de OLMAMALI."""
        from karadul.analyzers import list_analyzers

        all_analyzers = list_analyzers()
        for target_type, cls in all_analyzers.items():
            assert cls is not SwiftBinaryAnalyzer, (
                "SwiftBinaryAnalyzer registry'ye eklenmis! "
                "Bu MachOAnalyzer'i ezer."
            )

    def test_all_existing_analyzers_intact(self):
        """Tum mevcut analyzer kayitlari durmali."""
        from karadul.analyzers import list_analyzers

        all_analyzers = list_analyzers()

        # Bu tiplerin hepsinde birer analyzer kayitli olmali
        expected_types = [
            TargetType.JS_BUNDLE,
            TargetType.ELECTRON_APP,
            TargetType.MACHO_BINARY,
            TargetType.UNIVERSAL_BINARY,
            TargetType.GO_BINARY,
            TargetType.JAVA_JAR,
            TargetType.ANDROID_APK,
            TargetType.DOTNET_ASSEMBLY,
        ]
        for tt in expected_types:
            assert tt in all_analyzers, f"{tt} icin analyzer kayitli degil!"
