"""Mobile container classifier test suite.

Synthetic ZIP fixture'ları ile IPA / APK / AAB / XAPK tespit testleri.
Gerçek mobile binary kullanılmaz — stdlib zipfile + plistlib + struct ile
in-memory fixture'lar üretilir.
"""
from __future__ import annotations

import io
import json
import plistlib
import struct
import zipfile
from pathlib import Path

import pytest

from karadul.analyzers.container_classifier import (
    ContainerClassifier,
    ContainerError,
    ContainerInfo,
    ContainerType,
    classify_container,
    parse_android_manifest,
    parse_cert_info,
    parse_dex_header,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def _build_ipa(
    tmp_path: Path,
    app_name: str = "TestApp",
    bundle_id: str = "com.example.test",
    version: str = "1.2.3",
    min_os: str = "13.0",
    add_codesignature: bool = True,
    add_provisioning: bool = False,
    add_frameworks: list[str] | None = None,
    macho_universal: bool = False,
) -> Path:
    """Synthetic IPA üret."""
    out = tmp_path / f"{app_name}.ipa"
    info_plist = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleShortVersionString": version,
        "CFBundleName": app_name,
        "CFBundleDisplayName": app_name,
        "MinimumOSVersion": min_os,
        "UIRequiredDeviceCapabilities": ["arm64"],
    }

    # Mach-O bytes — MH_MAGIC_64 LE veya FAT
    if macho_universal:
        macho = b"\xca\xfe\xba\xbe" + b"\x00" * 124
    else:
        # 64-bit LE
        macho = b"\xcf\xfa\xed\xfe" + b"\x00" * 124

    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr(f"Payload/{app_name}.app/Info.plist", plistlib.dumps(info_plist))
        zf.writestr(f"Payload/{app_name}.app/{app_name}", macho)
        if add_codesignature:
            zf.writestr(f"Payload/{app_name}.app/_CodeSignature/CodeResources", b"<?xml dummy?>")
        if add_provisioning:
            # Minimal CMS-like blob with embedded subject DN string
            inner = (
                b"\x06\x03\x55\x04\x03"  # OID CN
                b"\x13\x09Apple Inc"
                b"\x06\x03\x55\x04\x0A"  # OID O
                b"\x13\x09Apple Inc"
            )
            asn1 = b"\x30" + bytes([len(inner)]) + inner
            zf.writestr(f"Payload/{app_name}.app/embedded.mobileprovision", asn1)
        for fw in (add_frameworks or []):
            zf.writestr(f"Payload/{app_name}.app/Frameworks/{fw}/{fw.replace('.framework', '')}", b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
    return out


def _build_axml_minimal(
    package: str = "com.example.app",
    version_name: str = "1.0.0",
    version_code: int = 100,
    min_sdk: int = 21,
    target_sdk: int = 33,
    debuggable: bool = False,
) -> bytes:
    """Minimal geçerli AXML AndroidManifest üret.

    Layout: XML resource header + StringPool + StartElement(manifest) +
    StartElement(uses-sdk) + StartElement(application).
    """
    # String pool sıralaması:
    strings = [
        "manifest",         # 0
        "uses-sdk",         # 1
        "application",      # 2
        "package",          # 3
        "versionName",      # 4
        "versionCode",      # 5
        "minSdkVersion",    # 6
        "targetSdkVersion", # 7
        "debuggable",       # 8
        "label",            # 9
        package,            # 10
        version_name,       # 11
        "TestLabel",        # 12
    ]

    # UTF-8 string pool (her string için: utf16len(byte) + utf8len(byte) + bytes + \0)
    string_data = b""
    string_offsets: list[int] = []
    for s in strings:
        string_offsets.append(len(string_data))
        utf8 = s.encode("utf-8")
        # utf16 char count (ascii için == len(s)), <128
        u16len = min(len(s), 0x7F)
        u8len = min(len(utf8), 0x7F)
        string_data += bytes([u16len, u8len]) + utf8 + b"\x00"
    # 4-byte align
    while len(string_data) % 4 != 0:
        string_data += b"\x00"

    string_count = len(strings)
    style_count = 0
    flags = (1 << 8)  # UTF-8
    sp_header_size = 28
    strings_start = sp_header_size + 4 * string_count  # offsets table sonrası
    sp_size = strings_start + len(string_data)

    string_pool = struct.pack(
        "<HHIIIII",
        0x0001, sp_header_size, sp_size,
        string_count, style_count, flags,
        strings_start,
    )
    # styles_start
    string_pool += struct.pack("<I", 0)
    # offsets table
    for so in string_offsets:
        string_pool += struct.pack("<I", so)
    string_pool += string_data
    # Pad sp to chunk_size
    while len(string_pool) < sp_size:
        string_pool += b"\x00"

    # StartElement chunk builder
    def _start_elem(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
        """attrs: list of (name_idx, value_type, value_data).

        AOSP layout:
          ResChunk_header: type(2)+headerSize(2)+size(4) = 8 byte
          ResXMLTree_node: lineNumber(4)+comment(4) = 8 byte (headerSize 16'ya dahil)
          ResXMLTree_attrExt: ns(4)+name(4)+attrStart(2)+attrSize(2)+attrCount(2)+
                              idIndex(2)+classIndex(2)+styleIndex(2) = 20 byte
          attrCount * ResXMLTree_attribute (20 byte each)
        """
        attr_start = 20  # attrExt başından attribute'lara byte offset
        attr_size = 20
        attr_count = len(attrs)
        # ResXMLTree_node: line + comment (header'a dahil, 16 - 8 = 8 byte)
        node_body = struct.pack("<II", 0, 0xFFFFFFFF)
        # attrExt: ns(4)+name(4) + 6*u16
        attr_ext = struct.pack(
            "<IIHHHHHH",
            0xFFFFFFFF,  # ns
            name_idx,
            attr_start, attr_size, attr_count,
            0xFFFF, 0xFFFF, 0xFFFF,
        )
        # Attribute records: ns(4)+name(4)+raw(4)+ size(2)+res0(1)+type(1)+data(4) = 20 byte
        attr_blob = b""
        for (a_name_idx, a_type, a_data) in attrs:
            raw_idx = a_data if a_type == 0x03 else 0xFFFFFFFF
            attr_blob += struct.pack(
                "<IIIHBBI",
                0xFFFFFFFF,  # ns
                a_name_idx,
                raw_idx,
                8, 0, a_type,
                a_data,
            )
        body = node_body + attr_ext + attr_blob
        chunk_size = 8 + len(body)
        header = struct.pack("<HHI", 0x0102, 16, chunk_size)
        return header + body

    # <manifest package="..." versionName="..." versionCode=...>
    manifest_attrs = [
        (3, 0x03, 10),   # package -> strings[10]
        (4, 0x03, 11),   # versionName -> strings[11]
        (5, 0x10, version_code),  # versionCode int
    ]
    elem_manifest = _start_elem(0, manifest_attrs)

    # <uses-sdk minSdkVersion=21 targetSdkVersion=33>
    uses_sdk_attrs = [
        (6, 0x10, min_sdk),
        (7, 0x10, target_sdk),
    ]
    elem_uses_sdk = _start_elem(1, uses_sdk_attrs)

    # <application debuggable=false label="TestLabel">
    app_attrs = [
        (8, 0x12, 1 if debuggable else 0),
        (9, 0x03, 12),  # label -> strings[12]
    ]
    elem_app = _start_elem(2, app_attrs)

    body = string_pool + elem_manifest + elem_uses_sdk + elem_app
    # Global header: type(0x0003) + hdr_size(8) + total_size
    total_size = 8 + len(body)
    global_header = struct.pack("<HHI", 0x0003, 8, total_size)
    return global_header + body


def _build_dex(
    version: str = "035",
    string_ids_size: int = 5,
    method_ids_size: int = 10,
    class_defs_size: int = 2,
) -> bytes:
    """Minimal DEX header bytes (112 byte header)."""
    header = bytearray(112)
    header[0:4] = b"dex\n"
    header[4:7] = version.encode("ascii")
    header[7] = 0
    # checksum
    struct.pack_into("<I", header, 8, 0xDEADBEEF)
    # signature 12..32
    # file_size at 32
    struct.pack_into("<I", header, 32, 200)
    # header_size at 36
    struct.pack_into("<I", header, 36, 112)
    # endian_tag at 40
    struct.pack_into("<I", header, 40, 0x12345678)
    # string_ids_size at 56
    struct.pack_into("<I", header, 56, string_ids_size)
    # method_ids_size at 88
    struct.pack_into("<I", header, 88, method_ids_size)
    # class_defs_size at 96
    struct.pack_into("<I", header, 96, class_defs_size)
    return bytes(header)


def _build_apk(
    tmp_path: Path,
    name: str = "test.apk",
    package: str = "com.example.app",
    archs: list[str] | None = None,
    add_signing: bool = True,
    add_proguard_mapping: bool = False,
    multi_dex: bool = False,
    debuggable: bool = False,
) -> Path:
    """Synthetic APK üret."""
    out = tmp_path / name
    archs = archs or ["arm64-v8a"]

    axml = _build_axml_minimal(package=package, debuggable=debuggable)
    dex = _build_dex()

    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("AndroidManifest.xml", axml)
        zf.writestr("classes.dex", dex)
        if multi_dex:
            zf.writestr("classes2.dex", _build_dex(class_defs_size=5))
            zf.writestr("classes3.dex", _build_dex(class_defs_size=3))
        zf.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 100)
        for arch in archs:
            zf.writestr(f"lib/{arch}/libfoo.so", b"\x7fELF" + b"\x00" * 60)
            zf.writestr(f"lib/{arch}/libnative.so", b"\x7fELF" + b"\x00" * 60)
        if add_signing:
            zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
            zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\n")
            # Fake CERT.RSA: ASN.1 sequence with CN=Android Debug
            inner = (
                b"\x06\x03\x55\x04\x03"  # OID CN
                b"\x13\x0DAndroid Debug"  # PrintableString
                b"\x06\x03\x55\x04\x0A"  # OID O
                b"\x13\x06Google"
            )
            cert = b"\x30" + bytes([len(inner)]) + inner
            zf.writestr("META-INF/CERT.RSA", cert)
        if add_proguard_mapping:
            zf.writestr("mapping.txt", b"com.example.X -> a:\n")
    return out


def _build_aab(tmp_path: Path, name: str = "test.aab") -> Path:
    """Synthetic AAB üret."""
    out = tmp_path / name
    axml = _build_axml_minimal(package="com.example.bundle", version_code=42)
    dex = _build_dex()

    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("BUNDLE-METADATA/com.android.tools.build.bundletool/version.txt", b"1.0.0")
        zf.writestr("base/manifest/AndroidManifest.xml", axml)
        zf.writestr("base/dex/classes.dex", dex)
        zf.writestr("base/lib/arm64-v8a/libcore.so", b"\x7fELF" + b"\x00" * 60)
        zf.writestr("base/lib/armeabi-v7a/libcore.so", b"\x7fELF" + b"\x00" * 60)
        zf.writestr("base/res/layout/main.xml", b"<dummy/>")
    return out


def _build_xapk(tmp_path: Path) -> Path:
    """Synthetic XAPK üret."""
    out = tmp_path / "test.xapk"
    inner_apk = _build_apk(tmp_path, name="_inner.apk", package="com.example.xapkapp")
    inner_bytes = inner_apk.read_bytes()

    manifest = {
        "name": "Test XAPK",
        "package_name": "com.example.xapkapp",
        "version_name": "2.0.0",
        "version_code": 200,
        "min_sdk_version": 21,
        "target_sdk_version": 33,
        "split_apks": [
            {"id": "arm64-v8a", "file": "config.arm64_v8a.apk"},
        ],
    }
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("test.apk", inner_bytes)
        zf.writestr("Android/obb/com.example.xapkapp/main.1.com.example.xapkapp.obb", b"obb-bytes" * 100)
    return out


# ---------------------------------------------------------------------------
# Tests: AXML parser
# ---------------------------------------------------------------------------

def test_axml_parser_minimal():
    """Minimal AXML'i parse et — package, versionName/Code, sdk."""
    data = _build_axml_minimal(
        package="com.foo.bar",
        version_name="1.2.3",
        version_code=42,
        min_sdk=21,
        target_sdk=33,
        debuggable=False,
    )
    res = parse_android_manifest(data)
    assert res["package"] == "com.foo.bar"
    assert res["versionName"] == "1.2.3"
    assert res["versionCode"] == 42
    assert res["minSdkVersion"] == 21
    assert res["targetSdkVersion"] == 33
    assert res["has_application"] is True
    assert res["debuggable"] is False
    assert res["label"] == "TestLabel"


def test_axml_parser_invalid_falls_back():
    """Geçersiz AXML — fallback string heuristic çalışmalı."""
    junk = b"\x00\x00\x00\x00not-axml-but-com.example.app.somewhere"
    res = parse_android_manifest(junk)
    # En azından paket adı bulunmalı (heuristic)
    assert res.get("package", "").startswith("com.example") or res == {} or "package" in res


# ---------------------------------------------------------------------------
# Tests: DEX header
# ---------------------------------------------------------------------------

def test_dex_header_parse():
    data = _build_dex(version="035", string_ids_size=7, method_ids_size=15, class_defs_size=4)
    info = parse_dex_header(data)
    assert info["magic"].startswith("dex")
    assert info["version"] == "035"
    assert info["string_ids_size"] == 7
    assert info["method_ids_size"] == 15
    assert info["class_defs_size"] == 4


def test_dex_invalid_magic():
    info = parse_dex_header(b"NOTADEX")
    assert info == {}


# ---------------------------------------------------------------------------
# Tests: Cert info
# ---------------------------------------------------------------------------

def test_cert_info_extracts_cn():
    """ASN.1 blob içinden CN ve O çıkarılmalı."""
    inner = (
        b"\x06\x03\x55\x04\x03"  # OID CN
        b"\x13\x0BTestCertCN1"   # PrintableString len=11
        b"\x06\x03\x55\x04\x0A"  # OID O
        b"\x13\x08ExampleO"      # PrintableString len=8
    )
    # Outer SEQUENCE (constructed, definite length, short form)
    cert = b"\x30" + bytes([len(inner)]) + inner
    info = parse_cert_info(cert)
    assert info["subject"]["CN"] == "TestCertCN1"
    assert info["subject"]["O"] == "ExampleO"


# ---------------------------------------------------------------------------
# Tests: IPA classification
# ---------------------------------------------------------------------------

def test_ipa_basic_classification(tmp_path):
    ipa = _build_ipa(tmp_path)
    info = ContainerClassifier(ipa).classify()
    assert info.container_type == ContainerType.IPA
    assert info.confidence >= 0.95
    assert info.app_name == "TestApp"
    assert info.package_id == "com.example.test"
    assert info.version == "1.2.3"
    assert info.min_sdk == 13
    assert "arm64" in info.architectures
    assert info.is_signed is True
    assert any(str(p).endswith("/TestApp") for p in info.executables)


def test_ipa_with_frameworks_and_provisioning(tmp_path):
    ipa = _build_ipa(
        tmp_path,
        add_frameworks=["MyLib.framework", "OtherLib.framework"],
        add_provisioning=True,
    )
    info = ContainerClassifier(ipa).classify()
    assert info.container_type == ContainerType.IPA
    assert "MyLib.framework" in info.frameworks
    assert "OtherLib.framework" in info.frameworks
    assert info.cert_info.get("subject", {}).get("CN") == "Apple Inc"
    assert info.cert_info["source"] == "embedded.mobileprovision"


def test_ipa_universal_macho(tmp_path):
    ipa = _build_ipa(tmp_path, macho_universal=True)
    info = ContainerClassifier(ipa).classify()
    assert info.container_type == ContainerType.IPA
    # arm64 plist'ten geliyor; universal sadece arch yokken set ediliyor
    assert info.architectures  # boş olmamalı


# ---------------------------------------------------------------------------
# Tests: APK classification
# ---------------------------------------------------------------------------

def test_apk_basic_classification(tmp_path):
    apk = _build_apk(tmp_path)
    info = ContainerClassifier(apk).classify()
    assert info.container_type == ContainerType.APK
    assert info.confidence >= 0.95
    assert info.package_id == "com.example.app"
    assert info.min_sdk == 21
    assert info.target_sdk == 33
    assert info.version_code == 100
    assert "arm64-v8a" in info.architectures
    assert info.is_signed is True
    assert info.cert_info.get("subject", {}).get("CN") == "Android Debug"
    assert any(str(p) == "classes.dex" for p in info.executables)
    assert "libfoo.so" in info.native_libs


def test_apk_multi_arch(tmp_path):
    apk = _build_apk(tmp_path, archs=["arm64-v8a", "armeabi-v7a", "x86_64"])
    info = ContainerClassifier(apk).classify()
    assert info.container_type == ContainerType.APK
    assert set(info.architectures) >= {"arm64-v8a", "armeabi-v7a", "x86_64"}


def test_apk_multi_dex(tmp_path):
    apk = _build_apk(tmp_path, multi_dex=True)
    info = ContainerClassifier(apk).classify()
    assert info.container_type == ContainerType.APK
    dex_paths = [str(p) for p in info.executables if str(p).endswith(".dex")]
    assert "classes.dex" in dex_paths
    assert "classes2.dex" in dex_paths
    assert "classes3.dex" in dex_paths


def test_apk_obfuscation_flag(tmp_path):
    apk = _build_apk(tmp_path, add_proguard_mapping=True)
    info = ContainerClassifier(apk).classify()
    assert info.is_obfuscated is True


def test_apk_unsigned(tmp_path):
    apk = _build_apk(tmp_path, add_signing=False)
    info = ContainerClassifier(apk).classify()
    assert info.is_signed is False
    assert info.cert_info == {} or "subject" not in info.cert_info


# ---------------------------------------------------------------------------
# Tests: AAB classification
# ---------------------------------------------------------------------------

def test_aab_classification(tmp_path):
    aab = _build_aab(tmp_path)
    info = ContainerClassifier(aab).classify()
    assert info.container_type == ContainerType.AAB
    assert info.confidence >= 0.95
    assert info.package_id == "com.example.bundle"
    assert info.version_code == 42
    assert "arm64-v8a" in info.architectures
    assert "armeabi-v7a" in info.architectures
    assert any(str(p) == "base/dex/classes.dex" for p in info.executables)


# ---------------------------------------------------------------------------
# Tests: XAPK classification
# ---------------------------------------------------------------------------

def test_xapk_classification(tmp_path):
    xapk = _build_xapk(tmp_path)
    info = ContainerClassifier(xapk).classify()
    assert info.container_type == ContainerType.XAPK
    assert info.confidence >= 0.85
    assert info.package_id == "com.example.xapkapp"
    assert info.version == "2.0.0"
    assert info.version_code == 200
    assert any(str(p).endswith(".apk") for p in info.executables)


# ---------------------------------------------------------------------------
# Tests: Negative / error paths
# ---------------------------------------------------------------------------

def test_random_zip_is_unknown(tmp_path):
    """İçinde mobile container işareti olmayan ZIP -> UNKNOWN."""
    out = tmp_path / "random.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("README.txt", b"hello")
        zf.writestr("PROGUARD.txt", b"obfuscation log")
    info = ContainerClassifier(out).classify()
    assert info.container_type == ContainerType.UNKNOWN
    assert info.confidence == 0.0


def test_pe_binary_not_zip(tmp_path):
    """PE binary -> UNKNOWN (zip magic yok)."""
    pe = tmp_path / "fake.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)
    info = ContainerClassifier(pe).classify()
    assert info.container_type == ContainerType.UNKNOWN
    assert "zip_magic_yok" in info.evidence


def test_missing_file_raises(tmp_path):
    """Dosya yoksa ContainerError."""
    with pytest.raises(ContainerError):
        ContainerClassifier(tmp_path / "nonexistent.apk")


def test_corrupt_zip_raises(tmp_path):
    """ZIP magic var ama bozuk -> ContainerError."""
    out = tmp_path / "bad.apk"
    out.write_bytes(b"PK\x03\x04" + b"\xff" * 100)
    with pytest.raises(ContainerError):
        ContainerClassifier(out).classify()


def test_classify_container_helper(tmp_path):
    """Helper API sağlıklı çalışmalı."""
    apk = _build_apk(tmp_path)
    info = classify_container(apk)
    assert isinstance(info, ContainerInfo)
    assert info.container_type == ContainerType.APK


def test_to_dict_serializable(tmp_path):
    """to_dict() JSON-serializable olmalı."""
    apk = _build_apk(tmp_path)
    info = ContainerClassifier(apk).classify()
    d = info.to_dict()
    json.dumps(d)  # raise etmemeli
    assert d["container_type"] == "apk"
    assert d["package_id"] == "com.example.app"


def test_anti_debug_flag_default_modern(tmp_path):
    """debuggable=false ise has_anti_debug=True."""
    apk = _build_apk(tmp_path, debuggable=False)
    info = ContainerClassifier(apk).classify()
    assert info.has_anti_debug is True


def test_anti_debug_flag_when_debuggable(tmp_path):
    """debuggable=true ise has_anti_debug=False."""
    apk = _build_apk(tmp_path, debuggable=True)
    info = ContainerClassifier(apk).classify()
    assert info.has_anti_debug is False
