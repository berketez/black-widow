"""Mobile container classifier (IPA / APK / AAB / XAPK).

Karadul v1.13 Dalga 1 Wave 3 — mobile-lite kapsamı:
sadece konteyner tipini tanır, iç yapı (manifest, mimari, executable, sertifika)
metadata'sı çıkarır. Decompile/disasm YAPMAZ — bunlar diğer analyzer'lara aittir.

Bağımlılık politikası: yalnızca stdlib (zipfile, plistlib, struct, xml.etree).
3rd-party kütüphaneye bağımlı değildir.

Desteklenen:
- IPA   : iOS .ipa (ZIP, Payload/<App>.app/ pattern'i)
- APK   : Android .apk (AndroidManifest.xml + classes*.dex)
- AAB   : Android App Bundle (BUNDLE-METADATA/ + base/manifest/)
- XAPK  : APK + manifest.json + (opsiyonel) .obb assetler

Sınırlamalar:
- AndroidManifest.xml binary parser: AXML chunk format'ının subset'i
  (StringPool + ResourceMap + StartElement). Sadece <manifest>, <uses-sdk>,
  <application> attribute'ları. Karmaşık StyledStrings yok.
- Cert info: META-INF/CERT.RSA için minimal ASN.1 BER parser, sadece subject
  ve issuer Distinguished Name string extract (CN=..., O=..., ...). Tam
  PKCS#7 / X.509 doğrulaması YAPMAZ.
- AAB: temel tespit + base/manifest/AndroidManifest.xml okur. Module split,
  asset packs, dynamic delivery destek YOK (sadece var/yok bilgisi).
- APK signature scheme v2/v3 (içerik-tabanlı imza): tespit edilir ama parse
  edilmez. v1 (jar imza) için META-INF içinde CERT.RSA aranır.

Author: karadul takımı
"""
from __future__ import annotations

import json
import logging
import plistlib
import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

# ZIP boyut güvenliği — ZIP-bomb koruması (mobile container makul üst sınır 1GB)
_MAX_CONTAINER_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
_MAX_ZIP_ENTRY_SIZE = 256 * 1024 * 1024       # 256 MB tek dosya
_MAX_AXML_SIZE = 8 * 1024 * 1024              # 8 MB AndroidManifest

# DEX magic: "dex\n035\0", "dex\n036\0", "dex\n037\0", "dex\n038\0", "dex\n039\0"
_DEX_MAGIC_PREFIX = b"dex\n"

# Mach-O magic (target.py ile uyumlu)
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # MH_MAGIC 32 BE
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 BE
    b"\xce\xfa\xed\xfe",  # MH_CIGAM 32 LE
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 LE
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC (universal)
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
}

# AXML (binary AndroidManifest) chunk type'ları
_AXML_HEADER_MAGIC = 0x00080003   # XML resource chunk (LE: 03 00 08 00)
_AXML_CHUNK_STRING_POOL = 0x001C0001
_AXML_CHUNK_RESOURCE_MAP = 0x00080180
_AXML_CHUNK_START_NS = 0x00100100
_AXML_CHUNK_END_NS = 0x00100101
_AXML_CHUNK_START_ELEMENT = 0x00100102
_AXML_CHUNK_END_ELEMENT = 0x00100103
_AXML_CHUNK_CDATA = 0x00100104

# AXML attribute value types
_AXML_TYPE_STRING = 0x03
_AXML_TYPE_INT_DEC = 0x10
_AXML_TYPE_INT_HEX = 0x11
_AXML_TYPE_INT_BOOL = 0x12

# AXML StringPool flags
_AXML_STR_FLAG_UTF8 = (1 << 8)

# Standart APK arch dizinleri
_KNOWN_ARCHS = {
    "arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64", "mips", "mips64",
}


# ---------------------------------------------------------------------------
# Data tipleri
# ---------------------------------------------------------------------------

class ContainerType(Enum):
    """Mobile container tipleri."""
    IPA = "ipa"
    APK = "apk"
    AAB = "aab"
    XAPK = "xapk"
    UNKNOWN = "unknown"


class ContainerError(Exception):
    """Container parse hatası (geri kazanılamaz)."""


@dataclass
class ContainerInfo:
    """Tespit edilen container bilgileri."""
    container_type: ContainerType
    container_path: Path
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)

    # Metadata
    app_name: str | None = None
    package_id: str | None = None
    version: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None

    # Mimari
    architectures: list[str] = field(default_factory=list)

    # Gömülü çalıştırılabilir dosyalar (zip iç path'leri)
    executables: list[Path] = field(default_factory=list)

    # İmza
    is_signed: bool = False
    cert_info: dict[str, Any] = field(default_factory=dict)

    # Framework / native lib
    frameworks: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)

    # Special flags
    is_obfuscated: bool = False
    has_anti_debug: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "container_type": self.container_type.value,
            "container_path": str(self.container_path),
            "confidence": round(self.confidence, 3),
            "evidence": list(self.evidence),
            "app_name": self.app_name,
            "package_id": self.package_id,
            "version": self.version,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "architectures": list(self.architectures),
            "executables": [str(p) for p in self.executables],
            "is_signed": self.is_signed,
            "cert_info": dict(self.cert_info),
            "frameworks": list(self.frameworks),
            "native_libs": list(self.native_libs),
            "is_obfuscated": self.is_obfuscated,
            "has_anti_debug": self.has_anti_debug,
        }


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

def _safe_read(zf: zipfile.ZipFile, name: str, max_size: int = _MAX_ZIP_ENTRY_SIZE) -> bytes:
    """ZIP içinden güvenli okuma (boyut sınırlı)."""
    info = zf.getinfo(name)
    if info.file_size > max_size:
        raise ContainerError(
            f"ZIP girdisi cok buyuk: {name} = {info.file_size} byte (limit {max_size})"
        )
    with zf.open(info, "r") as fh:
        return fh.read(max_size + 1)[:max_size]


def _is_zip(path: Path) -> bool:
    """Dosyanın ZIP magic'i taşıyıp taşımadığını kontrol et."""
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
        return head[:2] == b"PK" and len(head) == 4
    except OSError:
        return False


# ---------------------------------------------------------------------------
# AndroidManifest.xml binary (AXML) parser — minimal subset
# ---------------------------------------------------------------------------

def _parse_axml_string_pool(data: bytes, offset: int) -> tuple[list[str], int]:
    """AXML StringPool chunk'ı parse et. (strings, chunk_size) döndür.

    AOSP ResStringPool layout:
        chunk_header: type(u16=0x0001) + header_size(u16) + size(u32)
        string_count(u32) + style_count(u32) + flags(u32) +
        strings_start(u32) + styles_start(u32)
    """
    if offset + 28 > len(data):
        raise ContainerError("AXML string pool truncated")
    chunk_type = struct.unpack_from("<H", data, offset + 0)[0]
    header_size = struct.unpack_from("<H", data, offset + 2)[0]
    chunk_size = struct.unpack_from("<I", data, offset + 4)[0]
    if chunk_type != 0x0001:
        raise ContainerError(f"Beklenmeyen string pool tipi: 0x{chunk_type:04x}")

    # StringPool header (28 byte total): type(2)+hdr(2)+size(4)+strCount(4)+styleCount(4)+flags(4)+strOff(4)+styleOff(4)
    string_count = struct.unpack_from("<I", data, offset + 8)[0]
    style_count = struct.unpack_from("<I", data, offset + 12)[0]
    flags = struct.unpack_from("<I", data, offset + 16)[0]
    strings_start = struct.unpack_from("<I", data, offset + 20)[0]
    # styles_start = struct.unpack_from("<I", data, offset + 24)[0]

    is_utf8 = bool(flags & _AXML_STR_FLAG_UTF8)

    # String offset tablosu
    offsets_pos = offset + header_size
    if offsets_pos + 4 * string_count > len(data):
        raise ContainerError("AXML string offset table truncated")
    str_offsets = struct.unpack_from(f"<{string_count}I", data, offsets_pos)

    strings_pool_pos = offset + strings_start
    strings: list[str] = []
    for so in str_offsets:
        pos = strings_pool_pos + so
        if pos >= len(data):
            strings.append("")
            continue
        try:
            if is_utf8:
                # UTF-8: u16len-utf16 (mostly redundant) sonra u8len + bytes + null
                # Spec: AOSP frameworks/base/libs/androidfw/ResourceTypes.cpp
                # Format: [u8 utf16_len][u8 utf16_len_high?] [u8 utf8_len][u8 utf8_len_high?] bytes \0
                # Pratikte: ilk byte 0x80'den küçükse 1-byte len; aksi halde 2-byte big-endian.
                p = pos
                # utf16 length (skip)
                if p >= len(data):
                    strings.append("")
                    continue
                b1 = data[p]; p += 1
                if b1 & 0x80:
                    if p >= len(data):
                        strings.append("")
                        continue
                    p += 1
                # utf8 length
                if p >= len(data):
                    strings.append("")
                    continue
                u8a = data[p]; p += 1
                if u8a & 0x80:
                    if p >= len(data):
                        strings.append("")
                        continue
                    u8b = data[p]; p += 1
                    u8len = ((u8a & 0x7F) << 8) | u8b
                else:
                    u8len = u8a
                end = p + u8len
                if end > len(data):
                    strings.append("")
                    continue
                strings.append(data[p:end].decode("utf-8", errors="replace"))
            else:
                # UTF-16: u16 length (LE) + length*2 bytes + 0x0000 sonu
                if pos + 2 > len(data):
                    strings.append("")
                    continue
                length_word = struct.unpack_from("<H", data, pos)[0]
                p = pos + 2
                if length_word & 0x8000:
                    if p + 2 > len(data):
                        strings.append("")
                        continue
                    length_word2 = struct.unpack_from("<H", data, p)[0]
                    p += 2
                    length = ((length_word & 0x7FFF) << 16) | length_word2
                else:
                    length = length_word
                end = p + length * 2
                if end > len(data):
                    strings.append("")
                    continue
                strings.append(data[p:end].decode("utf-16-le", errors="replace"))
        except Exception:
            logger.debug("AXML string parse hatasi (pos=%d)", pos, exc_info=True)
            strings.append("")

    return strings, chunk_size


def _parse_axml_attributes(
    data: bytes,
    elem_offset: int,
    strings: list[str],
) -> dict[str, Any]:
    """StartElement chunk'ından attribute'ları çıkar.

    AOSP ResXMLTree layout:
        ResChunk_header (8 byte): type(2)+headerSize(2)+size(4)
        ResXMLTree_node (8 byte): lineNumber(4)+comment(4)
        ResXMLTree_attrExt (20 byte): ns(4)+name(4)+attrStart(2)+attrSize(2)+
                                       attrCount(2)+idIndex(2)+classIndex(2)+styleIndex(2)
        attrStart = byte offset from start of attrExt to first attribute (=20)
    """
    if elem_offset + 36 > len(data):
        return {}

    header_size = struct.unpack_from("<H", data, elem_offset + 2)[0]
    if header_size < 8:
        header_size = 16  # default for ResXMLTree_node
    # attrExt başlar header sonrası (header_size = 16 typically)
    ext_off = elem_offset + header_size
    if ext_off + 20 > len(data):
        return {}

    name_idx_in_ext = struct.unpack_from("<I", data, ext_off + 4)[0]  # noqa
    attr_start = struct.unpack_from("<H", data, ext_off + 8)[0]
    attr_size = struct.unpack_from("<H", data, ext_off + 10)[0]
    attr_count = struct.unpack_from("<H", data, ext_off + 12)[0]

    attrs: dict[str, Any] = {}
    base = ext_off + attr_start  # attr_start ext başından
    if attr_size == 0:
        attr_size = 20  # standart

    for i in range(attr_count):
        a_off = base + i * attr_size
        if a_off + 20 > len(data):
            break
        # ns(u32) + name(u32) + raw(u32) + typed_value:[size(u16)+res0(u8)+type(u8)+data(u32)]
        name_idx = struct.unpack_from("<I", data, a_off + 4)[0]
        raw_idx = struct.unpack_from("<I", data, a_off + 8)[0]
        # typed_value at a_off+12: size(u16)+res0(u8)+type(u8)+data(u32)
        val_type = data[a_off + 15]
        val_data = struct.unpack_from("<I", data, a_off + 16)[0]

        name = strings[name_idx] if 0 <= name_idx < len(strings) else f"attr_{name_idx}"

        if val_type == _AXML_TYPE_STRING and 0 <= val_data < len(strings):
            attrs[name] = strings[val_data]
        elif val_type in (_AXML_TYPE_INT_DEC, _AXML_TYPE_INT_HEX):
            attrs[name] = val_data
        elif val_type == _AXML_TYPE_INT_BOOL:
            attrs[name] = bool(val_data)
        else:
            # Diğer tipler (reference, color, dimension): raw değer
            if 0 <= raw_idx < len(strings) and strings[raw_idx]:
                attrs[name] = strings[raw_idx]
            else:
                attrs[name] = val_data

    return attrs


def parse_android_manifest(data: bytes) -> dict[str, Any]:
    """AXML AndroidManifest.xml binary'sini metadata dict'e parse et.

    Çıkarılan alanlar:
        package, versionName, versionCode, minSdkVersion, targetSdkVersion,
        compileSdkVersion, debuggable, label, has_application

    Hata toleranslı: parse başarısız olursa boş dict döner.
    """
    result: dict[str, Any] = {}
    if len(data) < 8:
        return result
    if len(data) > _MAX_AXML_SIZE:
        logger.warning("AXML cok buyuk (%d byte), parse atlandi", len(data))
        return result

    try:
        # Header: type(2)+hdr(2)+size(4) — beklenen 0x0003, 0x0008, total
        magic_type = struct.unpack_from("<H", data, 0)[0]
        if magic_type != 0x0003:
            # Bazı durumlarda XML resource chunk değil, plain bytes — string
            # heuristic fallback
            return _axml_string_fallback(data)

        # StringPool chunk (offset 8 sonrası)
        # Skip global header (8 byte)
        offset = 8
        if offset + 8 > len(data):
            return result

        sp_type = struct.unpack_from("<H", data, offset)[0]
        if sp_type != 0x0001:  # ResStringPool_type
            return _axml_string_fallback(data)

        strings, sp_size = _parse_axml_string_pool(data, offset)
        offset += sp_size

        # Sonra ResourceMap, sonra StartNamespace, sonra StartElement chunks
        # StartElement'leri tara, attribute extract et
        manifest_attrs: dict[str, Any] = {}
        uses_sdk_attrs: dict[str, Any] = {}
        application_attrs: dict[str, Any] = {}

        while offset + 8 <= len(data):
            ch_type = struct.unpack_from("<H", data, offset)[0]
            ch_size = struct.unpack_from("<I", data, offset + 4)[0]
            if ch_size == 0 or ch_size > len(data) - offset:
                break

            if ch_type == 0x0102:  # ResXMLTree_startElement
                # Element name string index at attrExt offset+4 (ns@0, name@4)
                ch_hdr_size = struct.unpack_from("<H", data, offset + 2)[0]
                if ch_hdr_size < 8:
                    ch_hdr_size = 16
                ext_off_local = offset + ch_hdr_size
                if ext_off_local + 8 <= len(data):
                    name_idx = struct.unpack_from("<I", data, ext_off_local + 4)[0]
                    elem_name = (
                        strings[name_idx]
                        if 0 <= name_idx < len(strings) else ""
                    )
                    attrs = _parse_axml_attributes(data, offset, strings)
                    if elem_name == "manifest":
                        manifest_attrs.update(attrs)
                    elif elem_name == "uses-sdk":
                        uses_sdk_attrs.update(attrs)
                    elif elem_name == "application":
                        application_attrs.update(attrs)

            offset += ch_size

        # Manifest attribute'larından sonuç oluştur
        if "package" in manifest_attrs:
            result["package"] = manifest_attrs["package"]
        if "versionName" in manifest_attrs:
            result["versionName"] = str(manifest_attrs["versionName"])
        if "versionCode" in manifest_attrs:
            try:
                result["versionCode"] = int(manifest_attrs["versionCode"])
            except (ValueError, TypeError):
                pass
        if "compileSdkVersion" in manifest_attrs:
            try:
                result["compileSdkVersion"] = int(manifest_attrs["compileSdkVersion"])
            except (ValueError, TypeError):
                pass

        if "minSdkVersion" in uses_sdk_attrs:
            try:
                result["minSdkVersion"] = int(uses_sdk_attrs["minSdkVersion"])
            except (ValueError, TypeError):
                pass
        if "targetSdkVersion" in uses_sdk_attrs:
            try:
                result["targetSdkVersion"] = int(uses_sdk_attrs["targetSdkVersion"])
            except (ValueError, TypeError):
                pass

        if application_attrs:
            result["has_application"] = True
            if "debuggable" in application_attrs:
                result["debuggable"] = bool(application_attrs["debuggable"])
            if "label" in application_attrs:
                result["label"] = str(application_attrs["label"])

        return result

    except (struct.error, IndexError, ContainerError) as e:
        logger.debug("AXML parse basarisiz: %s, string fallback", e)
        return _axml_string_fallback(data)


def _axml_string_fallback(data: bytes) -> dict[str, Any]:
    """AXML parse başarısızsa string regex fallback (java_binary.py gibi)."""
    import re
    result: dict[str, Any] = {}
    # Hem UTF-8 hem UTF-16-LE string'leri tara
    candidates: list[str] = []
    for s in re.findall(rb"[\x20-\x7e]{4,}", data):
        try:
            candidates.append(s.decode("ascii", errors="ignore"))
        except Exception:
            continue

    # package_id: en az 2 nokta, http değil, ilk eşleşme
    for c in candidates:
        if c.count(".") >= 2 and not c.startswith("http") and c.replace(".", "").replace("_", "").isalnum():
            result["package"] = c
            break

    return result


# ---------------------------------------------------------------------------
# DEX header parser
# ---------------------------------------------------------------------------

def parse_dex_header(data: bytes) -> dict[str, Any]:
    """DEX dosyasının header'ından temel bilgi çıkar (ilk 112 byte)."""
    if len(data) < 8 or not data.startswith(_DEX_MAGIC_PREFIX):
        return {}
    info: dict[str, Any] = {
        "magic": data[:8].decode("ascii", errors="replace"),
        "version": data[4:7].decode("ascii", errors="replace"),
    }
    if len(data) >= 112:
        try:
            checksum = struct.unpack_from("<I", data, 8)[0]
            file_size = struct.unpack_from("<I", data, 32)[0]
            header_size = struct.unpack_from("<I", data, 36)[0]
            string_ids_size = struct.unpack_from("<I", data, 56)[0]
            method_ids_size = struct.unpack_from("<I", data, 88)[0]
            class_defs_size = struct.unpack_from("<I", data, 96)[0]
            info.update({
                "checksum": checksum,
                "file_size": file_size,
                "header_size": header_size,
                "string_ids_size": string_ids_size,
                "method_ids_size": method_ids_size,
                "class_defs_size": class_defs_size,
            })
        except struct.error:
            pass
    return info


# ---------------------------------------------------------------------------
# X.509 / PKCS#7 minimal subject DN extractor
# ---------------------------------------------------------------------------

# Yaygın OID -> kısaltma
_OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}


def _decode_oid(data: bytes) -> str:
    """ASN.1 OID byte'larını dotted string'e çevir."""
    if not data:
        return ""
    parts: list[int] = []
    first = data[0]
    parts.append(first // 40)
    parts.append(first % 40)
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _extract_dn_strings(asn1_data: bytes) -> list[tuple[str, str]]:
    """ASN.1 BER blob içindeki tüm OID + sonraki string çiftlerini çıkar.

    Tam X.509 parse YAPMAZ — heuristic: OID tag (0x06) sonrası ilk string
    tag'ini (0x0C UTF8, 0x13 PrintableString, 0x16 IA5String, 0x14 T61) eşle.
    """
    pairs: list[tuple[str, str]] = []
    i = 0
    n = len(asn1_data)
    pending_oid: str | None = None

    while i < n - 1:
        tag = asn1_data[i]
        # Length parse (BER short/long form)
        if i + 1 >= n:
            break
        length_byte = asn1_data[i + 1]
        if length_byte < 0x80:
            length = length_byte
            content_off = i + 2
        else:
            num_octets = length_byte & 0x7F
            if num_octets == 0 or i + 2 + num_octets > n:
                i += 1
                continue
            length = 0
            for k in range(num_octets):
                length = (length << 8) | asn1_data[i + 2 + k]
            content_off = i + 2 + num_octets

        # Length overflow toleransı: spec dışı/bozuk DER blob'larında length
        # gerçek payload'tan büyük olabilir. Mümkün olduğunca kalan içerikle
        # devam et — taramayı durdurmadan.
        if content_off + length > n:
            length = max(0, n - content_off)

        content = asn1_data[content_off:content_off + length]

        if tag == 0x06:  # OID
            oid_str = _decode_oid(content)
            pending_oid = _OID_NAMES.get(oid_str, oid_str)
        elif tag in (0x0C, 0x13, 0x14, 0x16, 0x1E) and pending_oid:
            try:
                if tag == 0x1E:  # BMPString = UCS-2 BE
                    text = content.decode("utf-16-be", errors="replace")
                else:
                    text = content.decode("utf-8", errors="replace")
                pairs.append((pending_oid, text.strip("\x00").strip()))
                pending_oid = None
            except Exception:
                pending_oid = None

        # Constructed tag'lerse içine in (tag & 0x20)
        if tag & 0x20 and length > 0:
            i = content_off  # içine in
        else:
            i = content_off + length

    return pairs


def parse_cert_info(cert_data: bytes) -> dict[str, Any]:
    """CERT.RSA / CERT.DSA / CERT.EC byte'larından subject + issuer DN çıkar.

    PKCS#7 SignedData içinden X.509 sertifikasını arar (heuristic).
    Tam validation YAPMAZ — sadece string çıkarım.
    """
    info: dict[str, Any] = {}
    pairs = _extract_dn_strings(cert_data)

    # İlk N (CN, O, OU, C, L, ST) eşleşmesini subject olarak kabul et;
    # ikincisini issuer (kabaca). PKCS#7 format'ta önce subject, sonra issuer
    # gelmiyor olabilir — en azından bulunan tüm DN'leri liste tut.
    subject: dict[str, str] = {}
    issuer: dict[str, str] = {}
    seen_keys: set[str] = set()

    for key, val in pairs:
        if key in seen_keys and key in subject:
            # Tekrar ediyorsa issuer'a yaz
            issuer[key] = val
        else:
            subject[key] = val
            seen_keys.add(key)

    if subject:
        info["subject"] = subject
    if issuer:
        info["issuer"] = issuer
    info["dn_pairs"] = pairs[:50]  # ham çiftler (debug)
    return info


# ---------------------------------------------------------------------------
# Container Classifier
# ---------------------------------------------------------------------------

class ContainerClassifier:
    """Mobile container (IPA/APK/AAB/XAPK) sınıflandırıcı."""

    def __init__(self, archive_path: Path) -> None:
        self.archive_path = Path(archive_path)
        if not self.archive_path.exists():
            raise ContainerError(f"Dosya bulunamadi: {self.archive_path}")
        if not self.archive_path.is_file():
            raise ContainerError(f"Dosya degil: {self.archive_path}")

        size = self.archive_path.stat().st_size
        if size > _MAX_CONTAINER_SIZE:
            raise ContainerError(
                f"Container cok buyuk: {size} byte (limit {_MAX_CONTAINER_SIZE})"
            )
        self._size = size
        self._namelist: list[str] | None = None
        self._zf: zipfile.ZipFile | None = None

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def classify(self) -> ContainerInfo:
        """Container'ı sınıflandır ve metadata çıkar."""
        if not _is_zip(self.archive_path):
            return ContainerInfo(
                container_type=ContainerType.UNKNOWN,
                container_path=self.archive_path,
                confidence=0.0,
                evidence=["zip_magic_yok"],
            )

        try:
            with zipfile.ZipFile(self.archive_path, "r") as zf:
                self._zf = zf
                self._namelist = zf.namelist()
                ctype, conf, ev = self._detect_type()
                info = ContainerInfo(
                    container_type=ctype,
                    container_path=self.archive_path,
                    confidence=conf,
                    evidence=ev,
                )

                if ctype == ContainerType.IPA:
                    self._fill_ipa(info)
                elif ctype in (ContainerType.APK, ContainerType.XAPK):
                    self._fill_apk(info)
                elif ctype == ContainerType.AAB:
                    self._fill_aab(info)

                return info
        except zipfile.BadZipFile as e:
            raise ContainerError(f"Bozuk ZIP: {e}") from e
        except OSError as e:
            raise ContainerError(f"IO hatasi: {e}") from e
        finally:
            self._zf = None
            self._namelist = None

    def extract_metadata(self) -> dict[str, Any]:
        """classify() çağırıp dict olarak döner."""
        return self.classify().to_dict()

    def list_executables(self) -> list[Path]:
        """Container içindeki çalıştırılabilir dosyaların ZIP iç path'leri."""
        return self.classify().executables

    # -----------------------------------------------------------------------
    # Tip tespiti
    # -----------------------------------------------------------------------

    def _detect_type(self) -> tuple[ContainerType, float, list[str]]:
        """ZIP içeriğinden container tipini tespit et."""
        names = self._namelist or []
        names_lower = {n.lower() for n in names}
        ev: list[str] = []

        # IPA: Payload/<Name>.app/ pattern
        ipa_app_dirs = {
            n.split("/", 2)[1]
            for n in names
            if n.startswith("Payload/") and "/" in n[len("Payload/"):]
            and (n[len("Payload/"):].split("/", 1)[0].endswith(".app"))
        }
        has_info_plist = any(
            n.startswith("Payload/") and n.endswith(".app/Info.plist")
            for n in names
        )

        # APK işaretleri
        has_android_manifest = "AndroidManifest.xml" in names
        has_dex = any(
            (n == "classes.dex" or
             (n.startswith("classes") and n.endswith(".dex")))
            for n in names
        )
        has_resources_arsc = "resources.arsc" in names
        has_meta_inf = any(n.startswith("META-INF/") for n in names)

        # AAB işaretleri
        has_bundle_metadata = any(n.startswith("BUNDLE-METADATA/") for n in names)
        has_base_manifest = any(
            n.startswith("base/manifest/AndroidManifest.xml")
            or n == "base/manifest/AndroidManifest.xml"
            for n in names
        )
        has_base_dex = any(n.startswith("base/dex/") for n in names)

        # XAPK işaretleri
        has_xapk_manifest = "manifest.json" in names_lower
        has_obb = any(n.endswith(".obb") for n in names)
        has_apk_inside = any(n.endswith(".apk") for n in names)

        # IPA puanlama
        if ipa_app_dirs and has_info_plist:
            ev.append("payload_app_dir")
            ev.append("info_plist")
            score = 0.95
            # Mach-O executable opsiyonel ek kanıt
            for app_dir in ipa_app_dirs:
                exec_name = app_dir[:-4]  # .app strip
                exec_path = f"Payload/{app_dir}/{exec_name}"
                if exec_path in names:
                    ev.append("macho_executable_path")
                    score = min(0.99, score + 0.03)
                    break
            return ContainerType.IPA, score, ev
        elif ipa_app_dirs:
            ev.append("payload_app_dir")
            return ContainerType.IPA, 0.65, ev

        # XAPK önce (APK + manifest.json kombinasyonu) — APK'dan önce check
        if has_xapk_manifest and (has_obb or has_apk_inside):
            ev.append("xapk_manifest_json")
            if has_obb:
                ev.append("obb_asset_pack")
            if has_apk_inside:
                ev.append("inner_apk")
            return ContainerType.XAPK, 0.90, ev

        # AAB
        if has_bundle_metadata and has_base_manifest:
            ev.extend(["bundle_metadata", "base_manifest"])
            score = 0.95
            if has_base_dex:
                ev.append("base_dex")
            return ContainerType.AAB, score, ev
        elif has_bundle_metadata:
            ev.append("bundle_metadata")
            return ContainerType.AAB, 0.70, ev

        # APK
        if has_android_manifest and has_dex:
            ev.extend(["android_manifest", "classes_dex"])
            score = 0.95
            if has_resources_arsc:
                ev.append("resources_arsc")
                score = 0.97
            if has_meta_inf:
                ev.append("meta_inf")
            return ContainerType.APK, score, ev
        elif has_android_manifest:
            ev.append("android_manifest")
            return ContainerType.APK, 0.65, ev

        return ContainerType.UNKNOWN, 0.0, ["unknown_zip_layout"]

    # -----------------------------------------------------------------------
    # IPA dolgulama
    # -----------------------------------------------------------------------

    def _fill_ipa(self, info: ContainerInfo) -> None:
        """IPA için metadata + executable + framework + sertifika."""
        assert self._zf is not None and self._namelist is not None
        zf = self._zf
        names = self._namelist

        # .app dizini bul
        app_dir = None
        for n in names:
            if n.startswith("Payload/") and n.endswith(".app/"):
                app_dir = n.rstrip("/")
                break
            if n.startswith("Payload/") and "/" in n[len("Payload/"):]:
                first_seg = "Payload/" + n[len("Payload/"):].split("/", 1)[0]
                if first_seg.endswith(".app"):
                    app_dir = first_seg
                    break
        if not app_dir:
            return

        info.app_name = app_dir.split("/")[-1].replace(".app", "")

        # Info.plist parse
        plist_path = f"{app_dir}/Info.plist"
        if plist_path in names:
            try:
                plist_data = _safe_read(zf, plist_path)
                plist = plistlib.loads(plist_data)
                info.package_id = plist.get("CFBundleIdentifier")
                info.version = plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
                info.app_name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or info.app_name
                # Min iOS
                min_os = plist.get("MinimumOSVersion")
                if min_os:
                    try:
                        info.min_sdk = int(str(min_os).split(".")[0])
                    except ValueError:
                        pass
                # Mimari (UIRequiredDeviceCapabilities)
                caps = plist.get("UIRequiredDeviceCapabilities", [])
                if isinstance(caps, list):
                    arch_set: list[str] = []
                    for cap in caps:
                        if cap == "arm64":
                            arch_set.append("arm64")
                        elif cap == "armv7":
                            arch_set.append("armv7")
                    if arch_set:
                        info.architectures = arch_set
            except (plistlib.InvalidFileException, ValueError, ContainerError) as e:
                logger.debug("IPA Info.plist parse hata: %s", e)

        # Mach-O executable
        if info.app_name:
            exec_path = f"{app_dir}/{info.app_name}"
            if exec_path in names:
                info.executables.append(Path(exec_path))
                # Mach-O magic check + universal arch detect
                try:
                    head = _safe_read(zf, exec_path, max_size=4096)
                    if head[:4] in _MACHO_MAGICS:
                        # FAT/universal: 0xCAFEBABE BE veya 0xBEBAFECA LE
                        if head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                            # nfat_arch sonra arch listesi — kaba tespit
                            if not info.architectures:
                                info.architectures = ["universal"]
                        else:
                            if not info.architectures:
                                # 64 vs 32
                                if head[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
                                    info.architectures = ["arm64"]
                                else:
                                    info.architectures = ["armv7"]
                except (ContainerError, OSError):
                    pass

        # Frameworks
        fw_prefix = f"{app_dir}/Frameworks/"
        fw_set: set[str] = set()
        for n in names:
            if n.startswith(fw_prefix):
                rel = n[len(fw_prefix):]
                if "/" in rel:
                    fw_name = rel.split("/", 1)[0]
                    if fw_name.endswith(".framework") or fw_name.endswith(".dylib"):
                        fw_set.add(fw_name)
        info.frameworks = sorted(fw_set)

        # Code signing & provisioning
        cs_dir = f"{app_dir}/_CodeSignature/"
        provisioning = f"{app_dir}/embedded.mobileprovision"
        signed = any(n.startswith(cs_dir) for n in names) or provisioning in names
        info.is_signed = signed
        if provisioning in names:
            try:
                prov_data = _safe_read(zf, provisioning)
                info.cert_info = parse_cert_info(prov_data)
                info.cert_info.setdefault("source", "embedded.mobileprovision")
            except (ContainerError, OSError):
                pass

    # -----------------------------------------------------------------------
    # APK dolgulama
    # -----------------------------------------------------------------------

    def _fill_apk(self, info: ContainerInfo) -> None:
        """APK / XAPK için metadata + native libs + cert."""
        assert self._zf is not None and self._namelist is not None
        zf = self._zf
        names = self._namelist

        # XAPK ise ana APK'yı içeride bul (manifest.json'dan)
        manifest_target = None  # iç APK path'i
        if info.container_type == ContainerType.XAPK:
            inner_apks = [n for n in names if n.endswith(".apk")]
            if "manifest.json" in names:
                try:
                    mj = _safe_read(zf, "manifest.json")
                    md = json.loads(mj.decode("utf-8", errors="replace"))
                    info.app_name = md.get("name") or md.get("title")
                    info.package_id = md.get("package_name") or md.get("packageName")
                    info.version = md.get("version_name") or md.get("versionName")
                    vc = md.get("version_code") or md.get("versionCode")
                    if vc:
                        try:
                            info.version_code = int(vc)
                        except (ValueError, TypeError):
                            pass
                    if md.get("min_sdk_version"):
                        try:
                            info.min_sdk = int(md["min_sdk_version"])
                        except (ValueError, TypeError):
                            pass
                    if md.get("target_sdk_version"):
                        try:
                            info.target_sdk = int(md["target_sdk_version"])
                        except (ValueError, TypeError):
                            pass
                    archs = md.get("split_apks") or []
                    if isinstance(archs, list):
                        for sub in archs:
                            if isinstance(sub, dict):
                                cfg = sub.get("id") or ""
                                if cfg in _KNOWN_ARCHS:
                                    info.architectures.append(cfg)
                except (json.JSONDecodeError, ContainerError, OSError):
                    logger.debug("XAPK manifest.json parse fail", exc_info=True)
            # OBB sayısı:
            obb_count = sum(1 for n in names if n.endswith(".obb"))
            if obb_count > 0:
                info.evidence.append(f"obb_count={obb_count}")
            # XAPK için iç APK'yı executable olarak ekle
            for ia in inner_apks:
                info.executables.append(Path(ia))
            # XAPK detayları için iç APK manifestini parse etmek için "manifest_target"
            # bırak (bu sürümde yapmıyoruz — heavy)

        # AndroidManifest.xml parse (APK ana)
        if "AndroidManifest.xml" in names:
            try:
                ax_data = _safe_read(zf, "AndroidManifest.xml")
                ax = parse_android_manifest(ax_data)
                info.package_id = info.package_id or ax.get("package")
                info.version = info.version or ax.get("versionName")
                if info.version_code is None and "versionCode" in ax:
                    info.version_code = ax["versionCode"]
                if info.min_sdk is None and "minSdkVersion" in ax:
                    info.min_sdk = ax["minSdkVersion"]
                if info.target_sdk is None and "targetSdkVersion" in ax:
                    info.target_sdk = ax["targetSdkVersion"]
                if not info.app_name and "label" in ax:
                    info.app_name = ax["label"]
                # debuggable=False -> anti-debug ipucu
                if "debuggable" in ax:
                    info.has_anti_debug = (not ax["debuggable"])
                else:
                    # Default debuggable=false sayılır (Android 10+)
                    info.has_anti_debug = True
            except (ContainerError, OSError) as e:
                logger.debug("APK manifest okuma hata: %s", e)

        # Native libs ve mimariler
        archs_found: set[str] = set()
        native_libs: set[str] = set()
        for n in names:
            if n.startswith("lib/") and n.endswith(".so"):
                parts = n.split("/")
                if len(parts) >= 3:
                    arch = parts[1]
                    if arch in _KNOWN_ARCHS:
                        archs_found.add(arch)
                    native_libs.add(parts[-1])
                    info.executables.append(Path(n))
        if archs_found and not info.architectures:
            info.architectures = sorted(archs_found)
        elif archs_found:
            # XAPK'tan gelmiş olabilir, birleştir
            merged = set(info.architectures) | archs_found
            info.architectures = sorted(merged)
        info.native_libs = sorted(native_libs)

        # DEX dosyaları executable
        for n in names:
            if n == "classes.dex" or (n.startswith("classes") and n.endswith(".dex") and "/" not in n):
                info.executables.append(Path(n))

        # Obfuscation: kotlin yok, classes.dex var, çok fazla küçük dex sınıfı
        # Kompakt heuristic: META-INF/proguard veya proguard.txt yoksa ve
        # tüm package'lar kısa harfliyse — burada sadece dosya bazlı:
        has_proguard_meta = any("proguard" in n.lower() for n in names)
        has_mapping_txt = any(n.endswith("mapping.txt") for n in names)
        if has_proguard_meta or has_mapping_txt:
            info.is_obfuscated = True

        # Signing
        meta_inf = [n for n in names if n.startswith("META-INF/")]
        cert_files = [
            n for n in meta_inf
            if n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC")
        ]
        info.is_signed = bool(cert_files)
        if cert_files:
            try:
                cert_data = _safe_read(zf, cert_files[0])
                info.cert_info = parse_cert_info(cert_data)
                info.cert_info["scheme"] = "v1_jar_signing"
                info.cert_info["cert_file"] = cert_files[0]
            except (ContainerError, OSError):
                pass

    # -----------------------------------------------------------------------
    # AAB dolgulama
    # -----------------------------------------------------------------------

    def _fill_aab(self, info: ContainerInfo) -> None:
        """AAB için base/manifest okuma + module list."""
        assert self._zf is not None and self._namelist is not None
        zf = self._zf
        names = self._namelist

        # base/manifest/AndroidManifest.xml
        base_manifest = "base/manifest/AndroidManifest.xml"
        if base_manifest in names:
            try:
                ax_data = _safe_read(zf, base_manifest)
                ax = parse_android_manifest(ax_data)
                info.package_id = ax.get("package")
                info.version = ax.get("versionName")
                if "versionCode" in ax:
                    info.version_code = ax["versionCode"]
                if "minSdkVersion" in ax:
                    info.min_sdk = ax["minSdkVersion"]
                if "targetSdkVersion" in ax:
                    info.target_sdk = ax["targetSdkVersion"]
                if "label" in ax:
                    info.app_name = ax["label"]
            except (ContainerError, OSError):
                pass

        # base/dex/*.dex
        for n in names:
            if n.startswith("base/dex/") and n.endswith(".dex"):
                info.executables.append(Path(n))

        # base/lib/<arch>/*.so
        archs_found: set[str] = set()
        native_libs: set[str] = set()
        for n in names:
            if n.startswith("base/lib/") and n.endswith(".so"):
                parts = n.split("/")
                if len(parts) >= 4:
                    arch = parts[2]
                    if arch in _KNOWN_ARCHS:
                        archs_found.add(arch)
                    native_libs.add(parts[-1])
                    info.executables.append(Path(n))
        info.architectures = sorted(archs_found)
        info.native_libs = sorted(native_libs)

        # AAB BUNDLE-METADATA imza var mı? (com.android.tools.build.bundletool/...)
        if any(n.startswith("META-INF/") and (n.endswith(".RSA") or n.endswith(".DSA")) for n in names):
            info.is_signed = True
        else:
            # AAB tipik olarak Play App Signing tarafından imzalanır,
            # bundletool aşamasında imzasız olabilir
            info.is_signed = False

        # Module list (split modules)
        modules: set[str] = set()
        for n in names:
            if "/" in n:
                first = n.split("/", 1)[0]
                # base + diğer modüller (dynamic feature modules)
                if first not in ("BUNDLE-METADATA", "META-INF") and "." not in first:
                    modules.add(first)
        if modules:
            info.evidence.append(f"aab_modules={sorted(modules)}")


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------

def classify_container(path: Path) -> ContainerInfo:
    """Tek-seferlik sınıflandırma helper."""
    return ContainerClassifier(path).classify()


__all__ = [
    "ContainerType",
    "ContainerInfo",
    "ContainerError",
    "ContainerClassifier",
    "classify_container",
    "parse_android_manifest",
    "parse_dex_header",
    "parse_cert_info",
]
