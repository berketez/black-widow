"""P19 / BICIM-04: düşman girdiden üretilen build.gradle ve .csproj enjeksiyonu.

Analiz edilen JAR/APK/.NET dosyasındaki `Main-Class`, Android `package`,
AssemblyRef adı ve dosya adı kökü üretilen Groovy/MSBuild betiğine kaçışsız
yazılıyordu; analist projeyi IDE'de açınca saldırganın komutu çalışırdı.
Bu testler eski kodda KIRMIZI, onarılmış kodda yeşildir. Hiçbir betik
çalıştırılmaz: yalnız üretilen metin incelenir.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest

from karadul.analyzers.dotnet_binary import DotNetBinaryAnalyzer
from karadul.analyzers.java_binary import JavaBinaryAnalyzer
from karadul.config import Config
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace

EVIL_MAIN_CLASS = [
    "a'; 'touch /tmp/pwn'.execute(); def z='",
    "com.x${'id'.execute()}",
    'com.x"; "id".execute(); "',
    "com.x.Main\rprintln 'x'",
    "com.x.Main\n",  # re.match(...$) sondaki satır sonunu kabul ederdi
    "com.x.Main\nprintln 'x'",
]
EVIL_PACKAGE = [
    'com.a.b${"touch /tmp/pwn".execute()}',
    'com.a.b"; println "x',
    "com.a.$rootProject.b",  # GString'te özellik erişimi
    "com.a.b'; 'id'.execute(); '",
]
EVIL_NUGET = [
    'Evil" /></ItemGroup><Target Name="BeforeBuild"><Exec Command="touch /tmp/pwn" />'
    '</Target><ItemGroup><PackageReference Include="y',
    'E" /><Target Name="B"><Exec Command="id"/></Target><X Include="',
    "Evil.Pkg --><Target Name=\"X\"/><!--",
    "a&b<c>",
    "Acme--Utils",  # kalıba uyar ama XML yorumunu bozar
]
EVIL_ASSEMBLY_NAME = (
    'x</AssemblyName></PropertyGroup><Target Name="BeforeBuild">'
    '<Exec Command="id"/></Target><PropertyGroup><AssemblyName>y'
)

_GROOVY_EXEC_MARKERS = (".execute()", "${", "println", "$rootProject", "\r")


@pytest.fixture
def java() -> JavaBinaryAnalyzer:
    return JavaBinaryAnalyzer(Config())


@pytest.fixture
def dotnet() -> DotNetBinaryAnalyzer:
    return DotNetBinaryAnalyzer(Config())


def _assert_inert_gradle(text: str, evil: str) -> None:
    for marker in _GROOVY_EXEC_MARKERS:
        assert marker not in text, (marker, text)
    # Değer hiçbir satırda (yorum dahil) geçmemeli
    first = evil.splitlines()[0] if evil.splitlines() else evil
    assert first not in text, text
    # Çift tırnaklı (GString) dizgi hiç yok
    assert '"' not in text


def _assert_inert_csproj(text: str) -> ET.Element:
    root = ET.fromstring(text)  # ayrıştırılabilir olmalı
    assert root.findall(".//Target") == []
    assert root.findall(".//Exec") == []
    assert root.findall(".//Import") == []
    return root


# ---------------------------------------------------------------- Gradle


@pytest.mark.parametrize("evil", EVIL_MAIN_CLASS)
def test_gradle_hostile_main_class_not_written(java, evil):
    text, rejected = java._build_gradle_and_rejections({"Main-Class": evil}, [])
    _assert_inert_gradle(text, evil)
    assert "mainClass" not in text
    assert [r["field"] for r in rejected] == ["Main-Class"]


@pytest.mark.parametrize("evil", EVIL_PACKAGE)
def test_gradle_hostile_android_package_not_written(java, evil):
    text, rejected = java._build_gradle_and_rejections(
        {"is_android": True, "package": evil}, [],
    )
    _assert_inert_gradle(text, evil)
    assert "namespace" not in text and "applicationId" not in text
    # Uydurma paket adı da yazılmaz
    assert "com.example.app" not in text
    assert [r["field"] for r in rejected] == ["package"]


@pytest.mark.parametrize("evil", EVIL_MAIN_CLASS[:3])
def test_generate_build_gradle_old_api_inert(java, evil):
    """Eski API (_generate_build_gradle) da aynı süzgeçten geçer."""
    _assert_inert_gradle(java._generate_build_gradle({"Main-Class": evil}, []), evil)
    _assert_inert_gradle(
        java._generate_build_gradle({"is_android": True, "package": evil}, []), evil,
    )


def test_gradle_overlong_name_rejected(java):
    name = "a" * 300
    text, rejected = java._build_gradle_and_rejections({"Main-Class": name}, [])
    assert name not in text
    assert rejected and rejected[0]["reason"] == "çok uzun"


def test_gradle_rejection_preview_is_inert(java):
    _, rejected = java._build_gradle_and_rejections(
        {"Main-Class": EVIL_MAIN_CLASS[0]}, [],
    )
    preview = rejected[0]["preview_percent_encoded"]
    for ch in "'\"$<>\n\r ;":
        assert ch not in preview


@pytest.mark.parametrize("name", ["com.example.Main", "Main", "com.example.Outer$Inner", "_a.b_c"])
def test_gradle_valid_main_class_kept(java, name):
    text, rejected = java._build_gradle_and_rejections({"Main-Class": name}, [])
    assert f"mainClass = '{name}'" in text
    assert rejected == []


def test_gradle_valid_android_package_kept(java):
    text, rejected = java._build_gradle_and_rejections(
        {"is_android": True, "package": "com.example.app"}, ["androidx", "gson"],
    )
    assert "namespace 'com.example.app'" in text
    assert "applicationId 'com.example.app'" in text
    assert "implementation 'androidx'" in text
    assert rejected == []
    assert '"' not in text


def test_gradle_hostile_dependency_not_written(java):
    text, rejected = java._build_gradle_and_rejections(
        {"Main-Class": "com.example.Main"}, ["gson", "x\"; 'id'.execute(); \""],
    )
    assert "implementation 'gson'" in text
    assert "execute" not in text
    assert [r["field"] for r in rejected] == ["dependency"]


def _write_jar(path: Path, manifest: str) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest)
        zf.writestr("com/x/Main.class", b"\xca\xfe\xba\xbe" + b"\x00" * 8)


def test_reconstruct_hostile_jar_end_to_end(java, tmp_path):
    jar = tmp_path / "evil.jar"
    _write_jar(jar, "Manifest-Version: 1.0\nMain-Class: " + EVIL_MAIN_CLASS[0] + "\n")
    ws = Workspace(tmp_path / "ws", "evil")
    ws.create()
    ti = TargetInfo(path=jar, name="evil", target_type=TargetType.JAVA_JAR,
                    language=Language.JAVA, file_size=jar.stat().st_size, file_hash="x")
    java._jadx_path = None  # araç yok: analiz edilen hiçbir şey çalıştırılmaz
    java.analyze_static(ti, ws)
    result = java.reconstruct(ti, ws)
    gradle = (ws.get_stage_dir("reconstructed") / "java_project" / "build.gradle").read_text()
    _assert_inert_gradle(gradle, EVIL_MAIN_CLASS[0])
    assert result.success is True
    assert [r["field"] for r in result.stats["rejected_values"]] == ["Main-Class"]


def test_reconstruct_hostile_apk_end_to_end(java, tmp_path):
    apk = tmp_path / "evil.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    b"\x03\x00\x08\x00" + EVIL_PACKAGE[0].encode() + b"\x00\x00")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
    ws = Workspace(tmp_path / "ws", "evil")
    ws.create()
    ti = TargetInfo(path=apk, name="evil", target_type=TargetType.ANDROID_APK,
                    language=Language.JAVA, file_size=apk.stat().st_size, file_hash="x")
    java._jadx_path = None
    java.analyze_static(ti, ws)
    result = java.reconstruct(ti, ws)
    gradle = (ws.get_stage_dir("reconstructed") / "java_project" / "build.gradle").read_text()
    _assert_inert_gradle(gradle, EVIL_PACKAGE[0])
    assert [r["field"] for r in result.stats["rejected_values"]] == ["package"]


# ---------------------------------------------------------------- csproj


@pytest.mark.parametrize("evil", EVIL_NUGET)
def test_csproj_hostile_dependency_not_written(dotnet, evil):
    text, rejected, stem = dotnet._csproj_and_rejections(
        {"assembly_name": "App"}, ["Newtonsoft.Json", evil],
    )
    root = _assert_inert_csproj(text)
    assert evil not in text
    includes = [e.get("Include") for e in root.iter("PackageReference")]
    assert includes == ["Newtonsoft.Json"]
    assert [r["field"] for r in rejected] == ["dependency"]
    assert stem == "App"


@pytest.mark.parametrize("evil", EVIL_NUGET[:2])
def test_generate_csproj_old_api_inert(dotnet, evil):
    """Eski API (_generate_csproj) da aynı süzgeçten geçer."""
    _assert_inert_csproj(dotnet._generate_csproj({"assembly_name": "App"}, [evil]))
    _assert_inert_csproj(dotnet._generate_csproj({"assembly_name": evil}, []))


def test_csproj_overlong_id_rejected(dotnet):
    long_id = "A" * 101
    text, rejected, _ = dotnet._csproj_and_rejections({"assembly_name": "App"}, [long_id])
    assert long_id not in text
    assert rejected and rejected[0]["reason"] == "çok uzun"


def test_csproj_unknown_assembly_ref_is_comment_only(dotnet):
    """Bilinmeyen (ama biçimce geçerli) AssemblyRef adı restore'a girmez."""
    text, rejected, _ = dotnet._csproj_and_rejections(
        {"assembly_name": "App"}, ["Newtonsoft.Json", "Acme.Evil.Loader"],
    )
    root = _assert_inert_csproj(text)
    includes = [e.get("Include") for e in root.iter("PackageReference")]
    assert includes == ["Newtonsoft.Json"]
    assert "Acme.Evil.Loader" in text  # yalnız yorumda, analist görsün
    assert rejected == []


def test_csproj_hostile_assembly_name(dotnet):
    text, rejected, stem = dotnet._csproj_and_rejections(
        {"assembly_name": EVIL_ASSEMBLY_NAME}, [],
    )
    root = _assert_inert_csproj(text)
    assert root.findall(".//AssemblyName") == []
    assert stem == "DecompiledProject"
    assert [r["field"] for r in rejected] == ["assembly_name"]


def test_csproj_valid_values_kept(dotnet):
    text, rejected, stem = dotnet._csproj_and_rejections(
        {"assembly_name": "My.App-1", "target_framework": ".NETCoreApp 6.0"},
        ["Newtonsoft.Json", "Serilog"],
    )
    root = _assert_inert_csproj(text)
    assert root.find(".//AssemblyName").text == "My.App-1"
    assert [e.get("Include") for e in root.iter("PackageReference")] == [
        "Newtonsoft.Json", "Serilog",
    ]
    assert "net6.0" in text
    assert stem == "My.App-1" and rejected == []


def test_dotnet_reconstruct_hostile_end_to_end(dotnet, tmp_path):
    ws = Workspace(tmp_path / "ws", "net")
    ws.create()
    sd = ws.get_stage_dir("static")
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "dotnet_analysis.json").write_text(json.dumps({
        "metadata": {"assembly_name": EVIL_ASSEMBLY_NAME.replace("/", "")},
        "dependencies": ["Newtonsoft.Json", EVIL_NUGET[1]],
    }))
    ti = TargetInfo(path=tmp_path / "x.dll", name="x", target_type=TargetType.DOTNET_ASSEMBLY,
                    language=Language.CSHARP, file_size=1, file_hash="x")
    result = dotnet.reconstruct(ti, ws)
    proj = ws.get_stage_dir("reconstructed") / "dotnet_project"
    files = sorted(p.name for p in proj.glob("*.csproj"))
    assert files == ["DecompiledProject.csproj"]
    _assert_inert_csproj((proj / files[0]).read_text())
    assert sorted(r["field"] for r in result.stats["rejected_values"]) == [
        "assembly_name", "dependency",
    ]
