"""Java/Kotlin Binary Analyzer test suite.

.class magic bytes detection, constant pool parsing,
Kotlin metadata tespiti ve JAR/WAR/EAR analiz testleri.

Gercek binary olmadan calismali -- mock data kullanir.
"""

from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.java_binary import (
    JavaBinaryAnalyzer,
    _CLASS_MAGIC,
    _CP_CLASS,
    _CP_UTF8,
    _JAVA_VERSION_MAP,
    _KOTLIN_METADATA_ANNOTATION,
    _KOTLIN_JVM_ANNOTATIONS,
    _detect_kotlin_from_strings,
)
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace


# --------------------------------------------------------------------------
# Helpers: mock .class dosyasi olusturma
# --------------------------------------------------------------------------

def _build_class_bytes(
    this_class: str = "com/example/MyClass",
    super_class: str = "java/lang/Object",
    methods: list[tuple[str, str]] | None = None,
    fields: list[tuple[str, str]] | None = None,
    interfaces: list[str] | None = None,
    extra_strings: list[str] | None = None,
    major_version: int = 61,  # Java 17
    minor_version: int = 0,
) -> bytes:
    """Minimal gecerli .class dosyasi olustur.

    Constant pool'da UTF8 ve Class entry'leri, fields, methods, interfaces.
    """
    buf = io.BytesIO()

    # Magic
    buf.write(_CLASS_MAGIC)
    # Minor, Major version
    buf.write(struct.pack(">HH", minor_version, major_version))

    # Constant pool olustur
    cp_entries: list[tuple[int, bytes]] = []  # (tag, data)
    utf8_index: dict[str, int] = {}

    def add_utf8(s: str) -> int:
        if s in utf8_index:
            return utf8_index[s]
        encoded = s.encode("utf-8")
        cp_entries.append((_CP_UTF8, struct.pack(">H", len(encoded)) + encoded))
        idx = len(cp_entries)  # 1-indexed
        utf8_index[s] = idx
        return idx

    def add_class(name: str) -> int:
        name_idx = add_utf8(name)
        cp_entries.append((_CP_CLASS, struct.pack(">H", name_idx)))
        return len(cp_entries)

    # this_class ve super_class
    this_cls_idx = add_class(this_class)
    super_cls_idx = add_class(super_class)

    # Interfaces
    iface_indices = []
    if interfaces:
        for iface in interfaces:
            iface_indices.append(add_class(iface))

    # Method ve field isimleri
    method_pairs = methods or []
    field_pairs = fields or []

    method_indices = []
    for name, desc in method_pairs:
        n_idx = add_utf8(name)
        d_idx = add_utf8(desc)
        method_indices.append((n_idx, d_idx))

    field_indices = []
    for name, desc in field_pairs:
        n_idx = add_utf8(name)
        d_idx = add_utf8(desc)
        field_indices.append((n_idx, d_idx))

    # Extra strings (Kotlin annotation'lari vs.)
    if extra_strings:
        for s in extra_strings:
            add_utf8(s)

    # Constant pool yaz
    cp_count = len(cp_entries) + 1  # 1-indexed, index 0 unused
    buf.write(struct.pack(">H", cp_count))
    for tag, data in cp_entries:
        buf.write(struct.pack("B", tag))
        buf.write(data)

    # Access flags
    buf.write(struct.pack(">H", 0x0021))  # ACC_PUBLIC | ACC_SUPER
    # this_class, super_class
    buf.write(struct.pack(">H", this_cls_idx))
    buf.write(struct.pack(">H", super_cls_idx))

    # Interfaces
    buf.write(struct.pack(">H", len(iface_indices)))
    for iface_idx in iface_indices:
        buf.write(struct.pack(">H", iface_idx))

    # Fields
    buf.write(struct.pack(">H", len(field_indices)))
    for n_idx, d_idx in field_indices:
        buf.write(struct.pack(">H", 0x0001))  # ACC_PUBLIC
        buf.write(struct.pack(">H", n_idx))
        buf.write(struct.pack(">H", d_idx))
        buf.write(struct.pack(">H", 0))  # no attributes

    # Methods
    buf.write(struct.pack(">H", len(method_indices)))
    for n_idx, d_idx in method_indices:
        buf.write(struct.pack(">H", 0x0001))  # ACC_PUBLIC
        buf.write(struct.pack(">H", n_idx))
        buf.write(struct.pack(">H", d_idx))
        buf.write(struct.pack(">H", 0))  # no attributes

    # Attributes
    buf.write(struct.pack(">H", 0))

    return buf.getvalue()


def _build_jar(tmp_path: Path, class_entries: dict[str, bytes],
               manifest: str | None = None,
               extra_files: dict[str, bytes] | None = None) -> Path:
    """Mock JAR dosyasi olustur."""
    jar_path = tmp_path / "test.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        for name, data in class_entries.items():
            zf.writestr(name, data)
        if manifest:
            zf.writestr("META-INF/MANIFEST.MF", manifest)
        if extra_files:
            for name, data in extra_files.items():
                zf.writestr(name, data)
    return jar_path


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture
def analyzer(config: Config) -> JavaBinaryAnalyzer:
    return JavaBinaryAnalyzer(config)


@pytest.fixture
def simple_class_bytes() -> bytes:
    """Basit bir Java class dosyasi (com.example.MyClass)."""
    return _build_class_bytes(
        this_class="com/example/MyClass",
        super_class="java/lang/Object",
        methods=[
            ("<init>", "()V"),
            ("main", "([Ljava/lang/String;)V"),
            ("getUser", "()Lcom/example/User;"),
        ],
        fields=[
            ("name", "Ljava/lang/String;"),
            ("age", "I"),
        ],
        interfaces=["java/io/Serializable"],
        major_version=61,
    )


@pytest.fixture
def kotlin_class_bytes() -> bytes:
    """Kotlin annotation'lari iceren class dosyasi."""
    return _build_class_bytes(
        this_class="com/example/KotlinApp",
        super_class="java/lang/Object",
        methods=[
            ("main", "([Ljava/lang/String;)V"),
            ("fetchData", "(Ljava/lang/String;)V"),
        ],
        extra_strings=[
            _KOTLIN_METADATA_ANNOTATION,
            "kotlin/jvm/JvmStatic",
            "kotlin/jvm/JvmName",
            "kotlin.coroutines.Continuation",
            "kotlinx.coroutines.CoroutineScope",
            "kotlin.Metadata",
        ],
    )


@pytest.fixture
def mock_class_file(tmp_path: Path, simple_class_bytes: bytes) -> Path:
    """Gecici dizinde .class dosyasi."""
    p = tmp_path / "MyClass.class"
    p.write_bytes(simple_class_bytes)
    return p


@pytest.fixture
def mock_jar(tmp_path: Path, simple_class_bytes: bytes) -> Path:
    """Gecici dizinde test.jar."""
    return _build_jar(
        tmp_path,
        class_entries={
            "com/example/MyClass.class": simple_class_bytes,
            "com/example/util/Helper.class": _build_class_bytes(
                this_class="com/example/util/Helper",
            ),
        },
        manifest="Manifest-Version: 1.0\nMain-Class: com.example.MyClass\n",
    )


@pytest.fixture
def mock_kotlin_jar(tmp_path: Path, kotlin_class_bytes: bytes) -> Path:
    """Kotlin class'lari iceren mock JAR."""
    return _build_jar(
        tmp_path,
        class_entries={
            "com/example/KotlinApp.class": kotlin_class_bytes,
        },
        extra_files={
            "kotlin/kotlin.kotlin_builtins": b"kotlin builtins data",
            "META-INF/kotlin-stdlib.kotlin_module": b"module data",
        },
        manifest="Manifest-Version: 1.0\nMain-Class: com.example.KotlinApp\n",
    )


@pytest.fixture
def mock_target(mock_jar: Path) -> TargetInfo:
    return TargetInfo(
        path=mock_jar,
        name="test",
        target_type=TargetType.JAVA_JAR,
        language=Language.JAVA,
        file_size=mock_jar.stat().st_size,
        file_hash="abc123",
    )


@pytest.fixture
def mock_class_target(mock_class_file: Path) -> TargetInfo:
    return TargetInfo(
        path=mock_class_file,
        name="MyClass",
        target_type=TargetType.JAVA_JAR,
        language=Language.JAVA,
        file_size=mock_class_file.stat().st_size,
        file_hash="abc123",
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    ws = Workspace(tmp_path / "workspace", "test_java")
    ws.create()
    return ws


# --------------------------------------------------------------------------
# Test: .class magic bytes detection
# --------------------------------------------------------------------------

class TestClassMagicDetection:
    """0xCAFEBABE magic bytes detection testleri."""

    def test_class_file_detected(self, analyzer: JavaBinaryAnalyzer, mock_class_file: Path):
        """Tek .class dosyasi can_handle ile tespit edilmeli."""
        target = TargetInfo(
            path=mock_class_file, name="MyClass",
            target_type=TargetType.JAVA_JAR, language=Language.JAVA,
            file_size=100, file_hash="x",
        )
        assert analyzer.can_handle(target) is True

    def test_non_class_file_rejected(self, analyzer: JavaBinaryAnalyzer, tmp_path: Path):
        """Rastgele binary .class olarak tespit edilmemeli."""
        fake = tmp_path / "notjava.class"
        fake.write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 100)
        target = TargetInfo(
            path=fake, name="notjava",
            target_type=TargetType.UNKNOWN, language=Language.UNKNOWN,
            file_size=104, file_hash="x",
        )
        assert analyzer.can_handle(target) is False

    def test_cafebabe_without_extension(self, analyzer: JavaBinaryAnalyzer, tmp_path: Path):
        """Uzantisi olmayan ama CAFEBABE magic'li dosya tespit edilmeli."""
        class_data = _build_class_bytes()
        f = tmp_path / "mystery_binary"
        f.write_bytes(class_data)
        target = TargetInfo(
            path=f, name="mystery",
            target_type=TargetType.UNKNOWN, language=Language.UNKNOWN,
            file_size=len(class_data), file_hash="x",
        )
        assert analyzer.can_handle(target) is True

    def test_jar_extension_detected(self, analyzer: JavaBinaryAnalyzer, tmp_path: Path):
        """JAR uzantili dosya can_handle ile tespit edilmeli."""
        jar = tmp_path / "app.jar"
        jar.write_bytes(b"PK\x03\x04" + b"\x00" * 100)  # Gecersiz ZIP ama uzanti yeterli
        target = TargetInfo(
            path=jar, name="app",
            target_type=TargetType.JAVA_JAR, language=Language.JAVA,
            file_size=104, file_hash="x",
        )
        assert analyzer.can_handle(target) is True

    def test_war_extension_detected(self, analyzer: JavaBinaryAnalyzer, tmp_path: Path):
        """WAR uzantili dosya tespit edilmeli."""
        war = tmp_path / "webapp.war"
        war.write_bytes(b"PK\x03\x04")
        target = TargetInfo(
            path=war, name="webapp",
            target_type=TargetType.JAVA_JAR, language=Language.JAVA,
            file_size=4, file_hash="x",
        )
        assert analyzer.can_handle(target) is True


# --------------------------------------------------------------------------
# Test: Constant pool parsing
# --------------------------------------------------------------------------

class TestConstantPoolParse:
    """.class constant pool parse testleri."""

    def test_parse_this_class(self, analyzer: JavaBinaryAnalyzer, simple_class_bytes: bytes):
        """this_class dogru parse edilmeli."""
        info = analyzer._parse_class_file(simple_class_bytes)
        assert info["this_class"] == "com.example.MyClass"

    def test_parse_super_class(self, analyzer: JavaBinaryAnalyzer, simple_class_bytes: bytes):
        """super_class dogru parse edilmeli."""
        info = analyzer._parse_class_file(simple_class_bytes)
        assert info["super_class"] == "java.lang.Object"

    def test_parse_package(self, analyzer: JavaBinaryAnalyzer, simple_class_bytes: bytes):
        """Package dogru cikarilmali."""
        info = analyzer._parse_class_file(simple_class_bytes)
        assert info["package"] == "com.example"

    def test_parse_methods(self, analyzer: JavaBinaryAnalyzer, simple_class_bytes: bytes):
        """Method isimleri cikarilmali."""
        info = analyzer._parse_class_file(simple_class_bytes)
        method_names = [m["name"] for m in info["methods"]]
        assert "<init>" in method_names
        assert "main" in method_names
        assert "getUser" in method_names

    def test_parse_fields(self, analyzer: JavaBinaryAnalyzer, simple_class_bytes: bytes):
        """Field isimleri cikarilmali."""
        info = analyzer._parse_class_file(simple_class_bytes)
        field_names = [f["name"] for f in info["fields"]]
        assert "name" in field_names
        assert "age" in field_names

    def test_parse_interfaces(self, analyzer: JavaBinaryAnalyzer, simple_class_bytes: bytes):
        """Interface'ler cikarilmali."""
        info = analyzer._parse_class_file(simple_class_bytes)
        assert "java.io.Serializable" in info["interfaces"]

    def test_parse_java_version(self, analyzer: JavaBinaryAnalyzer, simple_class_bytes: bytes):
        """Java major version dogru cikarilmali."""
        info = analyzer._parse_class_file(simple_class_bytes)
        assert info["java_version"] == 61
        assert info["java_version_label"] == "Java 17"

    def test_parse_java8_version(self, analyzer: JavaBinaryAnalyzer):
        """Java 8 (major=52) dogru tespit edilmeli."""
        data = _build_class_bytes(major_version=52)
        info = analyzer._parse_class_file(data)
        assert info["java_version"] == 52
        assert info["java_version_label"] == "Java 8"

    def test_parse_invalid_data(self, analyzer: JavaBinaryAnalyzer):
        """Gecersiz veri ile parse hata vermemeli."""
        info = analyzer._parse_class_file(b"\x00\x01\x02\x03")
        assert info["this_class"] is None

    def test_parse_empty_data(self, analyzer: JavaBinaryAnalyzer):
        """Bos veri ile parse hata vermemeli."""
        info = analyzer._parse_class_file(b"")
        assert info["this_class"] is None

    def test_parse_from_path(self, analyzer: JavaBinaryAnalyzer, mock_class_file: Path):
        """Path'den .class parse edilebilmeli."""
        info = analyzer._parse_class_file(mock_class_file)
        assert info["this_class"] == "com.example.MyClass"

    def test_constant_pool_strings(self, analyzer: JavaBinaryAnalyzer, simple_class_bytes: bytes):
        """Constant pool'daki string'ler cikarilmali."""
        info = analyzer._parse_class_file(simple_class_bytes)
        strings = info["strings"]
        assert len(strings) > 0
        assert "com/example/MyClass" in strings


# --------------------------------------------------------------------------
# Test: JAR class extraction
# --------------------------------------------------------------------------

class TestJarClassExtraction:
    """JAR icinden class extraction testleri."""

    def test_parse_classes_from_jar(self, analyzer: JavaBinaryAnalyzer, mock_jar: Path):
        """JAR icindeki class'lar parse edilebilmeli."""
        results = analyzer._parse_classes_from_jar(mock_jar)
        assert len(results) == 2
        class_names = [r["this_class"] for r in results]
        assert "com.example.MyClass" in class_names
        assert "com.example.util.Helper" in class_names

    def test_jar_contents_analysis(self, analyzer: JavaBinaryAnalyzer, mock_jar: Path):
        """JAR icerik analizi class ve package sayimali."""
        info = analyzer._analyze_jar_contents(mock_jar)
        assert info["class_count"] == 2
        assert "com.example" in info["packages"]
        assert "com.example.util" in info["packages"]

    def test_jar_manifest_extraction(self, analyzer: JavaBinaryAnalyzer, mock_jar: Path):
        """MANIFEST.MF dogru parse edilmeli."""
        manifest = analyzer._extract_manifest(mock_jar)
        assert manifest.get("Main-Class") == "com.example.MyClass"
        assert manifest.get("Manifest-Version") == "1.0"


# --------------------------------------------------------------------------
# Test: Kotlin detection
# --------------------------------------------------------------------------

class TestKotlinDetection:
    """Kotlin tespiti testleri."""

    def test_kotlin_metadata_in_strings(self):
        """kotlin.Metadata string'i detected=True yapmalı."""
        strings = [_KOTLIN_METADATA_ANNOTATION, "some.other.String"]
        result = _detect_kotlin_from_strings(strings)
        assert result["detected"] is True
        assert any("Metadata" in e for e in result["evidence"])

    def test_kotlin_jvm_annotations(self):
        """@JvmStatic/@JvmName annotation'lari tespiti."""
        strings = ["kotlin/jvm/JvmStatic", "kotlin/jvm/JvmName"]
        result = _detect_kotlin_from_strings(strings)
        assert result["detected"] is True
        assert "JvmStatic" in result["jvm_annotations"]
        assert "JvmName" in result["jvm_annotations"]

    def test_kotlin_string_patterns(self):
        """kotlin./kotlinx. string pattern'leri tespiti."""
        strings = [
            "kotlin.coroutines.Continuation",
            "kotlin.reflect.KClass",
            "kotlinx.coroutines.CoroutineScope",
            "kotlinx.serialization.Serializable",
        ]
        result = _detect_kotlin_from_strings(strings)
        assert result["detected"] is True

    def test_no_kotlin_in_plain_java(self):
        """Sade Java class'ta Kotlin tespit edilmemeli."""
        strings = [
            "com/example/MyClass",
            "java/lang/Object",
            "java/lang/String",
        ]
        result = _detect_kotlin_from_strings(strings)
        assert result["detected"] is False

    def test_kotlin_class_parse(self, analyzer: JavaBinaryAnalyzer, kotlin_class_bytes: bytes):
        """Kotlin class dosyasinda kotlin_detected=True olmali."""
        info = analyzer._parse_class_file(kotlin_class_bytes)
        assert info["kotlin_detected"] is True
        assert len(info["kotlin_info"]["evidence"]) > 0

    def test_kotlin_jar_detection(self, analyzer: JavaBinaryAnalyzer, mock_kotlin_jar: Path):
        """Kotlin JAR'da kotlin_detected=True olmali."""
        jar_info = analyzer._analyze_jar_contents(mock_kotlin_jar)
        assert jar_info["kotlin_detected"] is True

    def test_kotlin_detect_from_jar(self, analyzer: JavaBinaryAnalyzer, mock_kotlin_jar: Path):
        """Kotlin JAR: full detection pipeline (JAR + bytecode)."""
        jar_info = analyzer._analyze_jar_contents(mock_kotlin_jar)
        class_details = analyzer._parse_classes_from_jar(mock_kotlin_jar)
        kotlin_info = analyzer._detect_kotlin(mock_kotlin_jar, jar_info, class_details)
        assert kotlin_info["detected"] is True


# --------------------------------------------------------------------------
# Test: Package structure recovery
# --------------------------------------------------------------------------

class TestPackageRecovery:
    """Package structure recovery testleri."""

    def test_single_class_package(self, analyzer: JavaBinaryAnalyzer, simple_class_bytes: bytes):
        """Tek class'tan package cikarilmali."""
        info = analyzer._parse_class_file(simple_class_bytes)
        assert info["package"] == "com.example"

    def test_default_package(self, analyzer: JavaBinaryAnalyzer):
        """Default package (no dots) class."""
        data = _build_class_bytes(this_class="MyClass")
        info = analyzer._parse_class_file(data)
        assert info["package"] is None or info["package"] == ""

    def test_deep_package(self, analyzer: JavaBinaryAnalyzer):
        """Derin package yapisi."""
        data = _build_class_bytes(this_class="com/example/deep/nested/pkg/DeepClass")
        info = analyzer._parse_class_file(data)
        assert info["package"] == "com.example.deep.nested.pkg"

    def test_jar_multiple_packages(self, analyzer: JavaBinaryAnalyzer, tmp_path: Path):
        """Birden fazla package iceren JAR."""
        jar = _build_jar(
            tmp_path,
            class_entries={
                "com/example/A.class": _build_class_bytes(this_class="com/example/A"),
                "com/example/sub/B.class": _build_class_bytes(this_class="com/example/sub/B"),
                "org/other/C.class": _build_class_bytes(this_class="org/other/C"),
            },
        )
        info = analyzer._analyze_jar_contents(jar)
        assert "com.example" in info["packages"]
        assert "com.example.sub" in info["packages"]
        assert "org.other" in info["packages"]


# --------------------------------------------------------------------------
# Test: Full analyze_static pipeline
# --------------------------------------------------------------------------

class TestAnalyzeStatic:
    """analyze_static integration testleri."""

    def test_jar_analysis_produces_result(
        self, analyzer: JavaBinaryAnalyzer, mock_target: TargetInfo, workspace: Workspace,
    ):
        """JAR analizi StageResult dondurmeli."""
        result = analyzer.analyze_static(mock_target, workspace)
        assert isinstance(result, StageResult)
        assert result.success is True
        assert result.stage_name == "static"
        assert result.duration_seconds >= 0

    def test_jar_stats_populated(
        self, analyzer: JavaBinaryAnalyzer, mock_target: TargetInfo, workspace: Workspace,
    ):
        """JAR analizi istatistikleri doldurmali."""
        result = analyzer.analyze_static(mock_target, workspace)
        assert result.stats["total_classes"] == 2
        assert result.stats["total_packages"] >= 1

    def test_class_file_analysis(
        self, analyzer: JavaBinaryAnalyzer, mock_class_target: TargetInfo, workspace: Workspace,
    ):
        """Tek .class dosyasi analizi calismali."""
        result = analyzer.analyze_static(mock_class_target, workspace)
        assert result.success is True
        assert result.stats["total_classes"] == 1

    def test_analysis_json_written(
        self, analyzer: JavaBinaryAnalyzer, mock_target: TargetInfo, workspace: Workspace,
    ):
        """Analiz sonucu JSON dosyasina yazilmali."""
        result = analyzer.analyze_static(mock_target, workspace)
        analysis_path = Path(result.artifacts["java_analysis"])
        assert analysis_path.exists()
        data = json.loads(analysis_path.read_text())
        assert "jar_info" in data
        assert "manifest" in data

    def test_kotlin_jar_analysis(
        self, analyzer: JavaBinaryAnalyzer, workspace: Workspace,
        mock_kotlin_jar: Path,
    ):
        """Kotlin JAR analizi kotlin_detected=True vermeli."""
        target = TargetInfo(
            path=mock_kotlin_jar, name="kotlin_test",
            target_type=TargetType.JAVA_JAR, language=Language.JAVA,
            file_size=mock_kotlin_jar.stat().st_size, file_hash="abc",
        )
        result = analyzer.analyze_static(target, workspace)
        assert result.success is True
        assert result.stats.get("kotlin_detected") is True


# --------------------------------------------------------------------------
# Test: Obfuscation detection
# --------------------------------------------------------------------------

class TestObfuscationDetection:
    """ProGuard/R8 obfuscation tespiti testleri."""

    def test_obfuscated_packages_detected(self, analyzer: JavaBinaryAnalyzer, tmp_path: Path):
        """Tek harfli paket isimleri obfuscation olarak tespit edilmeli."""
        jar = _build_jar(
            tmp_path,
            class_entries={
                f"{chr(ord('a') + i)}/{chr(ord('a') + j)}/A.class":
                    _build_class_bytes(this_class=f"{chr(ord('a') + i)}/{chr(ord('a') + j)}/A")
                for i in range(4)
                for j in range(3)
            },
        )
        info = analyzer._analyze_jar_contents(jar)
        obf = analyzer._detect_obfuscation(jar, info)
        assert obf["detected"] is True
        assert obf["type"] == "proguard_r8"

    def test_normal_packages_not_obfuscated(self, analyzer: JavaBinaryAnalyzer, mock_jar: Path):
        """Normal paket isimleri obfuscation olarak tespit edilmemeli."""
        info = analyzer._analyze_jar_contents(mock_jar)
        obf = analyzer._detect_obfuscation(mock_jar, info)
        assert obf["detected"] is False


# --------------------------------------------------------------------------
# Test: Dependency analysis
# --------------------------------------------------------------------------

class TestDependencyAnalysis:
    """Dependency tespit testleri."""

    def test_known_libs_detected(self, analyzer: JavaBinaryAnalyzer, tmp_path: Path):
        """Bilinen kutuphane paketleri tespit edilmeli."""
        jar = _build_jar(
            tmp_path,
            class_entries={
                "com/google/gson/Gson.class": _build_class_bytes(
                    this_class="com/google/gson/Gson",
                ),
                "io/reactivex/Observable.class": _build_class_bytes(
                    this_class="io/reactivex/Observable",
                ),
            },
        )
        info = analyzer._analyze_jar_contents(jar)
        deps = analyzer._analyze_dependencies(jar, info)
        assert "gson" in deps
        assert "rxjava" in deps


# --------------------------------------------------------------------------
# Test: Java version map
# --------------------------------------------------------------------------

class TestJavaVersionMap:
    """Java version mapping testleri."""

    def test_java8_version(self):
        assert _JAVA_VERSION_MAP[52] == "Java 8"

    def test_java11_version(self):
        assert _JAVA_VERSION_MAP[55] == "Java 11"

    def test_java17_version(self):
        assert _JAVA_VERSION_MAP[61] == "Java 17"

    def test_java21_version(self):
        assert _JAVA_VERSION_MAP[65] == "Java 21"
