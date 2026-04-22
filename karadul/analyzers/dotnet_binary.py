""".NET/C# binary analiz modulu.

.NET assembly'ler metadata olarak EN zengin kaynak:
- Tum class, method, field, property isimleri IL metadata'da
- NuGet paket referanslari
- String literalleri
- Attribute'ler (Serializable, DllImport, vb.)

Bytecode seviyesinde analiz:
- PE header + CLI header (.NET runtime marker) detection
- .NET metadata stream parse (#Strings, #US, #GUID, #~ tables)
- TypeDef / MethodDef table'lardan class/method recovery
- Assembly reference table'dan dependency extraction

Araclar:
- ilspycmd: .NET IL -> C# decompile (en iyi acik kaynak decompiler)
- monodis: IL disassembly (Mono)
- strings + dotnet metadata fallback

Beklenen basari: %95+ (.NET metadata en zengin)
"""

from __future__ import annotations

import io
import json
import logging
import re
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.analyzers.base import BaseAnalyzer
from karadul.analyzers import register_analyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.safe_subprocess import resolve_tool
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)

# PE format sabitleri
_PE_MAGIC = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"

# CLI header (ECMA-335) sabitleri
_CLI_HEADER_SIZE = 72
_METADATA_SIGNATURE = b"\x42\x53\x4A\x42"  # "BSJB" -- .NET metadata root

# .NET metadata table numaralari (ECMA-335 II.22)
_TABLE_MODULE = 0x00
_TABLE_TYPEREF = 0x01
_TABLE_TYPEDEF = 0x02
_TABLE_FIELD = 0x04
_TABLE_METHODDEF = 0x06
_TABLE_PARAM = 0x08
_TABLE_MEMBERREF = 0x0A
_TABLE_ASSEMBLYREF = 0x23
_TABLE_ASSEMBLY = 0x20


def _parse_pe_cli_header(data: bytes) -> dict[str, Any]:
    """PE dosyasindan CLI header ve .NET metadata bilgisi cikar.

    PE -> COFF -> Optional Header -> Data Directories -> CLI Header -> Metadata Root

    Returns:
        dict: has_cli, cli_header_rva, metadata_rva, runtime_version,
              entry_point, flags, is_ilonly, is_32bit_required
    """
    result: dict[str, Any] = {
        "has_cli": False,
        "runtime_version": None,
        "metadata_version": None,
        "is_ilonly": False,
        "is_32bit_required": False,
    }

    if len(data) < 128 or data[:2] != _PE_MAGIC:
        return result

    try:
        r = io.BytesIO(data)

        # DOS header: e_lfanew at offset 0x3C
        r.seek(0x3C)
        pe_offset = struct.unpack("<I", r.read(4))[0]

        if pe_offset + 4 > len(data):
            return result

        # PE signature
        r.seek(pe_offset)
        if r.read(4) != _PE_SIGNATURE:
            return result

        # COFF header (20 bytes)
        machine = struct.unpack("<H", r.read(2))[0]
        num_sections = struct.unpack("<H", r.read(2))[0]
        r.read(12)  # timestamp, symtab, num_symbols
        optional_header_size = struct.unpack("<H", r.read(2))[0]
        characteristics = struct.unpack("<H", r.read(2))[0]

        if optional_header_size == 0:
            return result

        # Optional header
        opt_start = r.tell()
        opt_magic = struct.unpack("<H", r.read(2))[0]

        # PE32 (0x10B) veya PE32+ (0x20B)
        is_pe32plus = (opt_magic == 0x20B)

        # NumberOfRvaAndSizes:
        # PE32:  at opt_start + 92  (28 standard + 64 windows-specific)
        # PE32+: at opt_start + 108 (24 standard + 84 windows-specific, no BaseOfData)
        if is_pe32plus:
            nrva_offset = opt_start + 108
        else:
            nrva_offset = opt_start + 92

        r.seek(nrva_offset)
        num_data_dirs = struct.unpack("<I", r.read(4))[0]

        if num_data_dirs <= 14:
            return result

        # Data directories baslangi: NumberOfRvaAndSizes'dan hemen sonra
        dd_start = nrva_offset + 4

        # Data directory[14] = CLI Header (COM Descriptor)
        r.seek(dd_start + 14 * 8)
        cli_rva = struct.unpack("<I", r.read(4))[0]
        cli_size = struct.unpack("<I", r.read(4))[0]

        if cli_rva == 0 or cli_size == 0:
            return result

        result["has_cli"] = True

        # Section table'dan RVA -> file offset donusumu
        section_table_offset = opt_start + optional_header_size
        r.seek(section_table_offset)

        sections = []
        for _ in range(num_sections):
            sec_data = r.read(40)
            if len(sec_data) < 40:
                break
            sec_name = sec_data[:8].rstrip(b"\x00").decode("ascii", errors="replace")
            virtual_size = struct.unpack("<I", sec_data[8:12])[0]
            virtual_addr = struct.unpack("<I", sec_data[12:16])[0]
            raw_size = struct.unpack("<I", sec_data[16:20])[0]
            raw_offset = struct.unpack("<I", sec_data[20:24])[0]
            sections.append({
                "name": sec_name,
                "virtual_addr": virtual_addr,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
            })

        def rva_to_offset(rva: int) -> int | None:
            """RVA'yi dosya offset'ine donustur."""
            for sec in sections:
                if sec["virtual_addr"] <= rva < sec["virtual_addr"] + sec["virtual_size"]:
                    return rva - sec["virtual_addr"] + sec["raw_offset"]
            return None

        # CLI header oku
        cli_offset = rva_to_offset(cli_rva)
        if cli_offset is None or cli_offset + _CLI_HEADER_SIZE > len(data):
            return result

        r.seek(cli_offset)
        cli_data = r.read(_CLI_HEADER_SIZE)

        cb = struct.unpack("<I", cli_data[0:4])[0]
        major_runtime = struct.unpack("<H", cli_data[4:6])[0]
        minor_runtime = struct.unpack("<H", cli_data[6:8])[0]
        result["runtime_version"] = f"{major_runtime}.{minor_runtime}"

        metadata_rva = struct.unpack("<I", cli_data[8:12])[0]
        metadata_size = struct.unpack("<I", cli_data[12:16])[0]
        flags = struct.unpack("<I", cli_data[16:20])[0]

        result["is_ilonly"] = bool(flags & 0x01)
        result["is_32bit_required"] = bool(flags & 0x02)

        # Metadata root oku
        meta_offset = rva_to_offset(metadata_rva)
        if meta_offset is None or meta_offset + 16 > len(data):
            return result

        r.seek(meta_offset)
        meta_sig = r.read(4)
        if meta_sig != _METADATA_SIGNATURE:
            return result

        # Metadata root: signature(4) + major(2) + minor(2) + reserved(4) + version_length(4)
        r.read(4)  # major, minor
        r.read(4)  # reserved
        version_len = struct.unpack("<I", r.read(4))[0]
        if version_len > 256:
            version_len = 256
        version_str = r.read(version_len).rstrip(b"\x00").decode("ascii", errors="replace")
        result["metadata_version"] = version_str

        # Stream headers parse
        # After version string (padded to 4-byte boundary)
        pad = (4 - (version_len % 4)) % 4
        r.read(pad)

        flags_meta = struct.unpack("<H", r.read(2))[0]
        num_streams = struct.unpack("<H", r.read(2))[0]

        streams: dict[str, tuple[int, int]] = {}
        for _ in range(min(num_streams, 10)):
            stream_offset = struct.unpack("<I", r.read(4))[0]
            stream_size = struct.unpack("<I", r.read(4))[0]
            # Stream name (null-terminated, padded to 4-byte boundary)
            name_bytes = b""
            while True:
                ch = r.read(1)
                if not ch or ch == b"\x00":
                    break
                name_bytes += ch
            # Pad to 4-byte boundary
            total_name_len = len(name_bytes) + 1  # +1 for null terminator
            pad = (4 - (total_name_len % 4)) % 4
            r.read(pad)
            stream_name = name_bytes.decode("ascii", errors="replace")
            streams[stream_name] = (meta_offset + stream_offset, stream_size)

        result["streams"] = {k: {"offset": v[0], "size": v[1]} for k, v in streams.items()}
        result["sections"] = [s["name"] for s in sections]
        result["_rva_to_offset"] = rva_to_offset
        result["_streams_raw"] = streams
        result["_meta_offset"] = meta_offset

    except (struct.error, OSError, IndexError, ValueError) as e:
        logger.debug("PE/CLI header parse hatasi: %s", e)

    return result


def _parse_strings_heap(data: bytes, offset: int, size: int) -> dict[int, str]:
    """#Strings heap'ini parse et: index -> string."""
    strings: dict[int, str] = {}
    if offset + size > len(data):
        return strings

    heap = data[offset:offset + size]
    pos = 0
    while pos < len(heap):
        end = heap.find(b"\x00", pos)
        if end == -1:
            break
        s = heap[pos:end].decode("utf-8", errors="replace")
        if s:
            strings[pos] = s
        pos = end + 1

    return strings


def _extract_metadata_tables(
    data: bytes, cli_info: dict, max_types: int = 500, max_methods: int = 2000,
) -> dict[str, Any]:
    """#~ stream'den TypeDef, MethodDef, AssemblyRef tablolarini parse et.

    ECMA-335 II.24 -- Metadata table structure.
    """
    result: dict[str, Any] = {
        "types": [],
        "methods": [],
        "assembly_refs": [],
    }

    streams = cli_info.get("_streams_raw", {})
    if "#~" not in streams and "#-" not in streams:
        return result

    # #~ (optimized) veya #- (unoptimized) table stream
    tilde_name = "#~" if "#~" in streams else "#-"
    tilde_offset, tilde_size = streams[tilde_name]

    if tilde_offset + tilde_size > len(data):
        return result

    # #Strings heap
    strings_heap: dict[int, str] = {}
    if "#Strings" in streams:
        s_off, s_size = streams["#Strings"]
        strings_heap = _parse_strings_heap(data, s_off, s_size)

    try:
        r = io.BytesIO(data)
        r.seek(tilde_offset)

        # Table stream header
        reserved = struct.unpack("<I", r.read(4))[0]
        major = struct.unpack("B", r.read(1))[0]
        minor = struct.unpack("B", r.read(1))[0]
        heap_sizes = struct.unpack("B", r.read(1))[0]
        r.read(1)  # reserved

        # String index size: 2 veya 4 bytes
        str_idx_size = 4 if (heap_sizes & 0x01) else 2
        guid_idx_size = 4 if (heap_sizes & 0x02) else 2
        blob_idx_size = 4 if (heap_sizes & 0x04) else 2

        # Valid tables bitmask (8 bytes)
        valid = struct.unpack("<Q", r.read(8))[0]
        sorted_tables = struct.unpack("<Q", r.read(8))[0]

        # Row counts for each present table
        row_counts: dict[int, int] = {}
        for i in range(64):
            if valid & (1 << i):
                row_counts[i] = struct.unpack("<I", r.read(4))[0]

        # Simplified coded index size calculation
        def coded_idx_size(tables: list[int], tag_bits: int) -> int:
            max_rows = max((row_counts.get(t, 0) for t in tables), default=0)
            return 4 if max_rows >= (1 << (16 - tag_bits)) else 2

        # TypeDefOrRef coded index (3 tables, 2-bit tag)
        typedef_or_ref_size = coded_idx_size([0x02, 0x01, 0x1B], 2)
        # ResolutionScope coded index (4 tables, 2-bit tag)
        resolution_scope_size = coded_idx_size([0x00, 0x01, 0x23, 0x1A], 2)
        # MemberRefParent coded index (5 tables, 3-bit tag)
        # HasConstant, HasCustomAttribute etc. -- simplified, skip for now

        # Table row sizes (simplified -- we only parse what we need)
        # We need to skip tables in order to reach TypeDef, MethodDef, AssemblyRef

        # The tables are serialized in order of table number
        # We'll compute the byte position for each table we care about

        tables_start = r.tell()

        # TypeDef table (0x02): Flags(4) + TypeName(str) + TypeNamespace(str)
        #   + Extends(TypeDefOrRef) + FieldList(idx) + MethodList(idx)
        method_idx_size = 4 if row_counts.get(_TABLE_METHODDEF, 0) >= 65536 else 2
        field_idx_size = 4 if row_counts.get(_TABLE_FIELD, 0) >= 65536 else 2
        param_idx_size = 4 if row_counts.get(_TABLE_PARAM, 0) >= 65536 else 2

        typedef_row_size = (
            4  # Flags
            + str_idx_size  # TypeName
            + str_idx_size  # TypeNamespace
            + typedef_or_ref_size  # Extends
            + field_idx_size  # FieldList
            + method_idx_size  # MethodList
        )

        # MethodDef table (0x06): RVA(4) + ImplFlags(2) + Flags(2)
        #   + Name(str) + Signature(blob) + ParamList(idx)
        methoddef_row_size = (
            4  # RVA
            + 2  # ImplFlags
            + 2  # Flags
            + str_idx_size  # Name
            + blob_idx_size  # Signature
            + param_idx_size  # ParamList
        )

        # AssemblyRef table (0x23): MajorVersion(2) + MinorVersion(2) + BuildNumber(2)
        #   + RevisionNumber(2) + Flags(4) + PublicKeyOrToken(blob)
        #   + Name(str) + Culture(str) + HashValue(blob)
        assemblyref_row_size = (
            2 + 2 + 2 + 2  # Version
            + 4  # Flags
            + blob_idx_size  # PublicKeyOrToken
            + str_idx_size  # Name
            + str_idx_size  # Culture
            + blob_idx_size  # HashValue
        )

        # Calculate offsets for each table by summing sizes of preceding tables
        # Table order: 0x00 (Module), 0x01 (TypeRef), 0x02 (TypeDef), ...
        # We use a simplified calculation

        # Module (0x00): 2 + str + str + guid + guid + guid
        module_row_size = 2 + str_idx_size * 2 + guid_idx_size * 3 if _TABLE_MODULE in row_counts else 0

        # TypeRef (0x01): ResolutionScope + TypeName(str) + TypeNamespace(str)
        typeref_row_size = resolution_scope_size + str_idx_size * 2 if _TABLE_TYPEREF in row_counts else 0

        # Skip to TypeDef
        current_offset = tables_start
        for table_num in range(64):
            if not (valid & (1 << table_num)):
                continue
            count = row_counts[table_num]

            if table_num == _TABLE_TYPEDEF:
                # Parse TypeDef rows
                r.seek(current_offset)
                for row_idx in range(min(count, max_types)):
                    row_data = r.read(typedef_row_size)
                    if len(row_data) < typedef_row_size:
                        break
                    ro = io.BytesIO(row_data)
                    flags = struct.unpack("<I", ro.read(4))[0]

                    if str_idx_size == 4:
                        name_idx = struct.unpack("<I", ro.read(4))[0]
                        ns_idx = struct.unpack("<I", ro.read(4))[0]
                    else:
                        name_idx = struct.unpack("<H", ro.read(2))[0]
                        ns_idx = struct.unpack("<H", ro.read(2))[0]

                    type_name = strings_heap.get(name_idx, "")
                    type_ns = strings_heap.get(ns_idx, "")

                    if type_name and type_name != "<Module>":
                        fqn = f"{type_ns}.{type_name}" if type_ns else type_name
                        result["types"].append({
                            "name": type_name,
                            "namespace": type_ns,
                            "full_name": fqn,
                            "flags": flags,
                        })
                current_offset += count * typedef_row_size
                continue

            if table_num == _TABLE_METHODDEF:
                # Parse MethodDef rows
                r.seek(current_offset)
                for row_idx in range(min(count, max_methods)):
                    row_data = r.read(methoddef_row_size)
                    if len(row_data) < methoddef_row_size:
                        break
                    ro = io.BytesIO(row_data)
                    rva = struct.unpack("<I", ro.read(4))[0]
                    impl_flags = struct.unpack("<H", ro.read(2))[0]
                    flags = struct.unpack("<H", ro.read(2))[0]

                    if str_idx_size == 4:
                        name_idx = struct.unpack("<I", ro.read(4))[0]
                    else:
                        name_idx = struct.unpack("<H", ro.read(2))[0]

                    method_name = strings_heap.get(name_idx, "")
                    if method_name:
                        result["methods"].append({
                            "name": method_name,
                            "flags": flags,
                        })
                current_offset += count * methoddef_row_size
                continue

            if table_num == _TABLE_ASSEMBLYREF:
                # Parse AssemblyRef rows
                r.seek(current_offset)
                for row_idx in range(min(count, 100)):
                    row_data = r.read(assemblyref_row_size)
                    if len(row_data) < assemblyref_row_size:
                        break
                    ro = io.BytesIO(row_data)
                    major_v = struct.unpack("<H", ro.read(2))[0]
                    minor_v = struct.unpack("<H", ro.read(2))[0]
                    build_v = struct.unpack("<H", ro.read(2))[0]
                    rev_v = struct.unpack("<H", ro.read(2))[0]
                    ro.read(4)  # flags
                    ro.read(blob_idx_size)  # PublicKeyOrToken

                    if str_idx_size == 4:
                        name_idx = struct.unpack("<I", ro.read(4))[0]
                    else:
                        name_idx = struct.unpack("<H", ro.read(2))[0]

                    ref_name = strings_heap.get(name_idx, "")
                    if ref_name:
                        result["assembly_refs"].append({
                            "name": ref_name,
                            "version": f"{major_v}.{minor_v}.{build_v}.{rev_v}",
                        })
                current_offset += count * assemblyref_row_size
                continue

            # Diger tablolari atla -- row size hesaplamak karmasik
            # Basitlestirilmis: bilinen tablo boyutlarini hesapla, bilinmeyenleri atla
            # Bu noktada TypeDef/MethodDef/AssemblyRef parse edildiyse geri kalan onemli degil
            # Row size'i bilinmeyen tabloyu atlayamayiz -> break
            if table_num == _TABLE_MODULE:
                current_offset += count * (2 + str_idx_size * 2 + guid_idx_size * 3)
            elif table_num == _TABLE_TYPEREF:
                current_offset += count * (resolution_scope_size + str_idx_size * 2)
            elif table_num == 0x03:  # FieldPtr (rare)
                current_offset += count * field_idx_size
            elif table_num == _TABLE_FIELD:
                current_offset += count * (2 + str_idx_size + blob_idx_size)
            elif table_num == 0x05:  # MethodPtr (rare)
                current_offset += count * method_idx_size
            else:
                # Bilinmeyen tablo -- daha fazla parse edemeyiz
                break

    except (struct.error, OSError, IndexError, ValueError) as e:
        logger.debug(".NET metadata table parse hatasi: %s", e)

    return result


@register_analyzer(TargetType.DOTNET_ASSEMBLY)
class DotNetBinaryAnalyzer(BaseAnalyzer):
    """.NET/C# assembly analiz motoru.

    IL metadata'dan neredeyse tam kaynak kodu kurtarir.
    PE+CLI header parse ile binary seviyede metadata extraction.
    ConfuserEx ve diger .NET obfuscator'lari tespit eder.
    """

    supported_types = [TargetType.DOTNET_ASSEMBLY]

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._ilspy_path = resolve_tool("ilspycmd")
        self._monodis_path = resolve_tool("monodis")

    @staticmethod
    def can_handle(target_info: TargetInfo) -> bool:
        """PE/.NET assembly mi kontrol et.

        PE header (MZ) + CLI header varligini dogrular.
        """
        path = target_info.path
        suffix = path.suffix.lower()

        if suffix in (".dll", ".exe"):
            try:
                with open(path, "rb") as f:
                    # PE magic: MZ
                    if f.read(2) != _PE_MAGIC:
                        return False
                    # .NET CLI header kontrolu
                    data = f.read(4096)
                    # "mscoree.dll" veya ".NET" string'i varsa .NET
                    return (
                        b"mscoree.dll" in data
                        or b".NETFramework" in data
                        or b".NETCoreApp" in data
                    )
            except (OSError, PermissionError):
                pass

        return False

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """.NET assembly statik analiz.

        Analiz adimlari:
        1. PE+CLI header parse (binary seviyede)
        2. .NET metadata tables parse (TypeDef, MethodDef, AssemblyRef)
        3. Assembly metadata cikarma (strings fallback)
        4. Obfuscation tespiti
        5. ILSpy/monodis ile decompile
        6. NuGet dependency tespiti
        """
        start = time.monotonic()
        result_data: dict[str, Any] = {}
        errors: list[str] = []
        target_path = target.path

        # 1. PE+CLI header parse
        try:
            raw_data = target_path.read_bytes()
        except OSError as e:
            errors.append(f"Dosya okunamadi: {e}")
            raw_data = b""

        cli_info = _parse_pe_cli_header(raw_data)
        result_data["cli_header"] = {
            k: v for k, v in cli_info.items() if not k.startswith("_")
        }

        # 2. .NET metadata tables parse
        if cli_info.get("has_cli") and raw_data:
            tables = _extract_metadata_tables(raw_data, cli_info)
            result_data["metadata_tables"] = {
                "types": tables["types"][:500],
                "methods": tables["methods"][:2000],
                "assembly_refs": tables["assembly_refs"],
            }
            # Namespace recovery
            namespaces_from_tables = set()
            for t in tables["types"]:
                ns = t.get("namespace", "")
                if ns and not ns.startswith("System.") and not ns.startswith("Microsoft."):
                    namespaces_from_tables.add(ns)
            result_data["namespaces_from_tables"] = sorted(namespaces_from_tables)
        else:
            result_data["metadata_tables"] = {"types": [], "methods": [], "assembly_refs": []}
            result_data["namespaces_from_tables"] = []

        # 3. Assembly metadata cikar (strings fallback + enrichment)
        metadata = self._extract_metadata(target_path)
        # Tablolardan gelen bilgiyi metadata ile birlestir
        if result_data["metadata_tables"]["types"]:
            metadata["type_count"] = len(result_data["metadata_tables"]["types"])
        if result_data["metadata_tables"]["methods"]:
            metadata["method_count"] = len(result_data["metadata_tables"]["methods"])
        # Namespace birlesimi
        ns_combined = set(metadata.get("namespaces", []))
        ns_combined.update(result_data.get("namespaces_from_tables", []))
        metadata["namespaces"] = sorted(ns_combined)[:300]
        result_data["metadata"] = metadata

        # 4. Obfuscation tespiti
        obf = self._detect_obfuscation(target_path, metadata)
        result_data["obfuscation"] = obf

        # 5. ILSpy ile decompile
        if self._ilspy_path:
            decompile_dir = workspace.get_stage_dir("static") / "decompiled_dotnet"
            decompiled = self._decompile_with_ilspy(target_path, decompile_dir)
            result_data["decompiled"] = decompiled
        elif self._monodis_path:
            il_output = self._disassemble_with_monodis(target_path, workspace)
            result_data["il_output"] = il_output
        else:
            errors.append("ilspycmd veya monodis bulunamadi")
            result_data["strings_info"] = self._extract_from_strings(target_path)

        # 6. NuGet dependency tespiti (references + assembly_refs birlesimi)
        deps = self._detect_nuget_packages(target_path, metadata)
        # AssemblyRef tablosundan ek dependency'ler
        for ref in result_data["metadata_tables"].get("assembly_refs", []):
            ref_name = ref.get("name", "")
            if ref_name and ref_name not in deps:
                # System/Microsoft haric
                if not ref_name.startswith("System") and not ref_name.startswith("mscorlib"):
                    deps.append(ref_name)
        result_data["dependencies"] = deps

        # Kaydet
        output_path = workspace.get_stage_dir("static") / "dotnet_analysis.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result_data, indent=2, default=str))

        duration = time.monotonic() - start
        return StageResult(
            stage_name="static",
            success=True,
            duration_seconds=duration,
            artifacts={"dotnet_analysis": str(output_path)},
            stats={
                "total_types": metadata.get("type_count", 0),
                "total_methods": metadata.get("method_count", 0),
                "obfuscated": obf.get("detected", False),
                "decompiled": bool(result_data.get("decompiled", {}).get("success")),
                "has_cli_header": cli_info.get("has_cli", False),
                "runtime_version": cli_info.get("runtime_version"),
            },
            errors=errors,
        )

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """.NET deobfuscation (ConfuserEx vb. icin)."""
        return StageResult(
            stage_name="deobfuscate", success=True, duration_seconds=0.0,
            artifacts={}, stats={}, errors=[],
        )

    def reconstruct(self, target: TargetInfo, workspace: Workspace) -> StageResult | None:
        """.NET proje yapisi olustur."""
        start = time.monotonic()
        output_dir = workspace.get_stage_dir("reconstructed") / "dotnet_project"
        output_dir.mkdir(parents=True, exist_ok=True)

        analysis_path = workspace.get_stage_dir("static") / "dotnet_analysis.json"
        if not analysis_path.exists():
            return None

        analysis = json.loads(analysis_path.read_text())
        metadata = analysis.get("metadata", {})

        # .csproj dosyasi olustur
        csproj = self._generate_csproj(metadata, analysis.get("dependencies", []))
        project_name = metadata.get("assembly_name", "DecompiledProject")
        (output_dir / f"{project_name}.csproj").write_text(csproj)

        # Decompiled kaynaklari kopyala
        decompiled = analysis.get("decompiled", {})
        if decompiled.get("success") and decompiled.get("output_dir"):
            src_dir = Path(decompiled["output_dir"])
            if src_dir.exists():
                shutil.copytree(src_dir, output_dir, dirs_exist_ok=True)

        return StageResult(
            stage_name="reconstruct", success=True,
            duration_seconds=time.monotonic() - start,
            artifacts={"dotnet_project": str(output_dir)},
            stats={"reconstructed": True}, errors=[],
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_metadata(self, path: Path) -> dict:
        """Assembly metadata cikar (strings + pattern matching)."""
        metadata: dict[str, Any] = {
            "assembly_name": path.stem,
            "type_count": 0,
            "method_count": 0,
            "namespaces": [],
            "references": [],
            "target_framework": None,
        }

        try:
            proc = subprocess.run(
                ["strings", str(path)],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode == 0:
                lines = proc.stdout.split("\n")
                namespaces = set()
                refs = set()

                for line in lines:
                    # Namespace pattern
                    ns_match = re.search(
                        r"((?:[A-Z][a-zA-Z0-9]*\.){2,}[A-Z][a-zA-Z0-9]*)", line,
                    )
                    if ns_match:
                        ns = ns_match.group(1)
                        if not ns.startswith("System.") and not ns.startswith("Microsoft."):
                            namespaces.add(ns.rsplit(".", 1)[0])

                    # Assembly reference
                    if "Version=" in line and "Culture=" in line:
                        ref_match = re.match(r"([^,]+),\s*Version=", line)
                        if ref_match:
                            refs.add(ref_match.group(1).strip())

                    # Target framework
                    if ".NETCoreApp" in line or ".NETFramework" in line:
                        metadata["target_framework"] = line.strip()[:100]

                metadata["namespaces"] = sorted(namespaces)[:200]
                metadata["references"] = sorted(refs)[:100]
                metadata["type_count"] = len(namespaces)
        except Exception as e:
            logger.warning(".NET metadata cikarma hatasi: %s", e)

        return metadata

    def _detect_obfuscation(self, path: Path, metadata: dict) -> dict:
        """.NET obfuscation tespiti."""
        result = {"detected": False, "type": None, "evidence": []}

        refs = metadata.get("references", [])
        namespaces = metadata.get("namespaces", [])

        # ConfuserEx tespiti
        if any("Confuser" in r for r in refs):
            result["detected"] = True
            result["type"] = "confuserex"
            result["evidence"].append("ConfuserEx reference bulundu")

        # Dotfuscator tespiti
        if any("Dotfuscator" in r for r in refs):
            result["detected"] = True
            result["type"] = "dotfuscator"
            result["evidence"].append("Dotfuscator reference bulundu")

        # Generic: cok fazla anlamsiz isim
        gibberish_count = sum(
            1 for ns in namespaces
            if re.match(r"^[a-z]{1,3}(\.[a-z]{1,3})*$", ns)
        )
        if gibberish_count > len(namespaces) * 0.4 and len(namespaces) > 10:
            result["detected"] = True
            result["type"] = result.get("type") or "unknown_obfuscator"
            result["evidence"].append(f"{gibberish_count} anlamsiz namespace")

        return result

    def _decompile_with_ilspy(self, path: Path, output_dir: Path) -> dict:
        """ILSpy CLI ile decompile."""
        result = {"success": False, "output_dir": str(output_dir), "source_files": 0}

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            cmd = [
                self._ilspy_path,
                str(path),
                "--project",
                "--outputdir", str(output_dir),
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=self.config.timeouts.subprocess,
            )

            if proc.returncode == 0 or output_dir.exists():
                cs_files = list(output_dir.rglob("*.cs"))
                result["success"] = True
                result["source_files"] = len(cs_files)
                logger.info("ILSpy decompile basarili: %d .cs dosyasi", len(cs_files))
            else:
                result["error"] = proc.stderr[:500] if proc.stderr else "Unknown"
        except subprocess.TimeoutExpired:
            result["error"] = "ILSpy timeout"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _disassemble_with_monodis(self, path: Path, workspace: Workspace) -> dict:
        """monodis ile IL disassembly."""
        result = {"success": False}
        try:
            output_path = workspace.get_stage_dir("static") / "il_disassembly.il"
            proc = subprocess.run(
                [self._monodis_path, "--output=" + str(output_path), str(path)],
                capture_output=True, text=True, timeout=120,
            )
            result["success"] = proc.returncode == 0
            result["output"] = str(output_path)
        except Exception as e:
            result["error"] = str(e)
        return result

    def _extract_from_strings(self, path: Path) -> dict:
        """Fallback: strings ile bilgi cikar."""
        result = {"classes": [], "methods": []}
        try:
            proc = subprocess.run(
                ["strings", str(path)],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode == 0:
                for line in proc.stdout.split("\n"):
                    # Method signature pattern
                    if "(" in line and ")" in line and "." in line:
                        parts = line.split("(")[0].strip()
                        if re.match(r"[A-Za-z_]\w*\.[A-Za-z_]\w*", parts):
                            result["methods"].append(parts)
                result["methods"] = result["methods"][:500]
        except Exception:
            logger.debug("Signature eslestirme basarisiz, atlaniyor", exc_info=True)
        return result

    def _detect_nuget_packages(self, path: Path, metadata: dict) -> list[str]:
        """NuGet paket referanslarini tespit et."""
        deps = []
        refs = metadata.get("references", [])

        known_packages = {
            "Newtonsoft.Json": "Newtonsoft.Json",
            "Serilog": "Serilog",
            "AutoMapper": "AutoMapper",
            "Dapper": "Dapper",
            "MediatR": "MediatR",
            "FluentValidation": "FluentValidation",
            "Polly": "Polly",
            "Swashbuckle": "Swashbuckle.AspNetCore",
            "NLog": "NLog",
            "EntityFramework": "Microsoft.EntityFrameworkCore",
            "Npgsql": "Npgsql",
            "StackExchange.Redis": "StackExchange.Redis",
            "RabbitMQ": "RabbitMQ.Client",
            "Hangfire": "Hangfire",
            "Quartz": "Quartz",
        }

        for ref in refs:
            for prefix, pkg in known_packages.items():
                if prefix in ref and pkg not in deps:
                    deps.append(pkg)

        return deps

    def _generate_csproj(self, metadata: dict, deps: list[str]) -> str:
        """.csproj dosyasi olustur."""
        framework = "net8.0"
        if metadata.get("target_framework"):
            tf = metadata["target_framework"]
            if "6.0" in tf:
                framework = "net6.0"
            elif "7.0" in tf:
                framework = "net7.0"
            elif "Framework" in tf:
                framework = "net48"

        pkg_refs = "\n".join(
            f'    <PackageReference Include="{d}" Version="*" />'
            for d in deps
        )

        return f"""<Project Sdk="Microsoft.NET.Sdk">
  <!-- Karadul v1.0 tarafindan olusturuldu -->
  <PropertyGroup>
    <TargetFramework>{framework}</TargetFramework>
    <AssemblyName>{metadata.get('assembly_name', 'DecompiledProject')}</AssemblyName>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
{pkg_refs}
  </ItemGroup>
</Project>
"""
