"""Delphi binary analiz modulu.

Delphi (Object Pascal) binary'leri su bilgileri tasir:
- RTTI (Run-Time Type Information): class isimleri, method isimleri, property bilgileri
- DFM (Delphi Form Module): form kaynaklari (UI layout, component isimleri)
- VMT (Virtual Method Table): class hiyerarsisi ve virtual method mapping
- PackageInfo: Delphi runtime package bilgileri
- Compiler version string'leri

Delphi binary'ler PE formati kullanir, ama .NET degildir.
RTTI ve DFM ayristirma ile yuksek oranda bilgi kurtarilabilir.

Beklenen basari: %70-80 (RTTI kalitesine bagli)
"""

from __future__ import annotations

import io
import json
import logging
import re
import struct
import time
from pathlib import Path
from typing import Any

from karadul.analyzers.base import BaseAnalyzer
from karadul.analyzers import register_analyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)

# PE magic bytes
_PE_MAGIC = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"

# Delphi RTTI sabitleri
# tkClass type kind (Delphi RTTI tkClass = 0x07 or 0x0D depending on version)
_TK_CLASS = 0x07
_TK_CLASS_V2 = 0x0D  # Newer Delphi versions

# Delphi compiler version tespiti icin string pattern'leri
_DELPHI_COMPILER_STRINGS = {
    "Borland Delphi": "Borland Delphi",
    "CodeGear Delphi": "CodeGear Delphi",
    "Embarcadero Delphi": "Embarcadero Delphi",
    "Embarcadero RAD Studio": "RAD Studio",
}

# Delphi version sabitleri (PE resource'da veya string'lerde)
_DELPHI_VERSION_MAP = {
    "Borland Delphi 3": "Delphi 3 (1997)",
    "Borland Delphi 4": "Delphi 4 (1998)",
    "Borland Delphi 5": "Delphi 5 (1999)",
    "Borland Delphi 6": "Delphi 6 (2001)",
    "Borland Delphi 7": "Delphi 7 (2002)",
    "Borland Delphi 2005": "Delphi 2005 (9)",
    "Borland Delphi 2006": "Delphi 2006 (10)",
    "CodeGear Delphi 2007": "Delphi 2007 (11)",
    "CodeGear Delphi 2009": "Delphi 2009 (12)",
    "Embarcadero Delphi XE": "Delphi XE (15)",
    "Embarcadero Delphi XE2": "Delphi XE2 (16)",
    "Embarcadero Delphi XE3": "Delphi XE3 (17)",
    "Embarcadero Delphi XE4": "Delphi XE4 (18)",
    "Embarcadero Delphi XE5": "Delphi XE5 (19)",
    "Embarcadero Delphi XE6": "Delphi XE6 (20)",
    "Embarcadero Delphi XE7": "Delphi XE7 (21)",
    "Embarcadero Delphi XE8": "Delphi XE8 (22)",
    "Embarcadero Delphi 10": "Delphi 10 Seattle",
    "Embarcadero Delphi 10.1": "Delphi 10.1 Berlin",
    "Embarcadero Delphi 10.2": "Delphi 10.2 Tokyo",
    "Embarcadero Delphi 10.3": "Delphi 10.3 Rio",
    "Embarcadero Delphi 10.4": "Delphi 10.4 Sydney",
    "Embarcadero Delphi 11": "Delphi 11 Alexandria",
    "Embarcadero Delphi 12": "Delphi 12 Athens",
}

# DFM binary format sabitleri
_DFM_TEXT_MAGIC = b"object "
_DFM_BIN_MAGIC_TPF0 = b"TPF0"

# Delphi VCL/FMX class isimleri (bilinen kontroller)
_KNOWN_DELPHI_CLASSES = {
    "TForm", "TButton", "TLabel", "TEdit", "TMemo", "TPanel",
    "TListBox", "TComboBox", "TCheckBox", "TRadioButton",
    "TMainMenu", "TPopupMenu", "TMenuItem",
    "TTimer", "TOpenDialog", "TSaveDialog",
    "TImage", "TScrollBox", "TGroupBox", "TTabControl",
    "TStatusBar", "TToolBar", "TActionList",
    "TDataModule", "TDataSource", "TClientDataSet",
    "TStringGrid", "TTreeView", "TListView",
    "TRichEdit", "TDateTimePicker", "TProgressBar",
    "TPageControl", "TTabSheet", "TSplitter",
    "TApplication", "TScreen", "TPrinter",
    "TThread", "TStringList", "TFileStream", "TMemoryStream",
}


def _detect_delphi_binary(data: bytes) -> dict[str, Any]:
    """Binary veride Delphi compiler izleri ve RTTI varligini kontrol et.

    Returns:
        dict: is_delphi, compiler_version, evidence, rtti_found
    """
    result: dict[str, Any] = {
        "is_delphi": False,
        "compiler_version": None,
        "compiler_label": None,
        "evidence": [],
        "rtti_found": False,
    }

    if not data or len(data) < 256:
        return result

    text = data.decode("ascii", errors="replace")

    # 1. Compiler version string'leri
    for marker, label in _DELPHI_COMPILER_STRINGS.items():
        if marker in text:
            result["is_delphi"] = True
            result["compiler_version"] = label
            result["evidence"].append(f"Compiler string: '{marker}'")
            # Daha spesifik versiyon ara
            for full_ver, ver_label in _DELPHI_VERSION_MAP.items():
                if full_ver in text:
                    result["compiler_label"] = ver_label
                    break
            break

    # 2. Delphi-specific runtime string'leri
    delphi_markers = [
        b"System.TObject",
        b"System.SysUtils",
        b"Vcl.Forms",
        b"FMX.Forms",
        b"System.Classes.TComponent",
        b"System.Classes.TPersistent",
        b"@System@@Finalization$qqrv",  # Delphi mangled name
        b"@System@TObject@",
        b"@Vcl@Forms@TForm@",
        b"@System@Classes@",
        b"SOFTWARE\\Borland\\Delphi",
        b"SOFTWARE\\Embarcadero\\BDS",
        b"rtl",  # Delphi RTL module
    ]

    marker_hits = 0
    for marker in delphi_markers:
        if marker in data:
            marker_hits += 1
            if marker_hits == 1:
                result["evidence"].append(f"Runtime marker: {marker[:40].decode('ascii', errors='replace')}")

    if marker_hits >= 3:
        result["is_delphi"] = True
        result["evidence"].append(f"{marker_hits} Delphi runtime marker bulundu")

    # 3. Delphi mangled name pattern: @Unit@Class@Method$qqr...
    delphi_mangled = re.findall(
        rb"@([A-Z][A-Za-z0-9_]+)@([A-Z][A-Za-z0-9_]+)@([A-Z][A-Za-z0-9_]+)\$qqr",
        data[:2_000_000],
    )
    if len(delphi_mangled) >= 5:
        result["is_delphi"] = True
        result["evidence"].append(f"{len(delphi_mangled)} Delphi mangled symbol bulundu")

    # 4. TObject VMT marker -- tum Delphi binary'lerde bulunur
    # VMT'nin basinda class ismi ve parent pointer bulunur
    tform_count = text.count("TForm")
    tobject_count = text.count("TObject")
    if tform_count >= 2 and tobject_count >= 3:
        result["is_delphi"] = True
        result["evidence"].append(
            f"TForm={tform_count}, TObject={tobject_count} referansi"
        )

    # 5. RTTI varligi kontrolu (tkClass byte + class ismi pattern)
    # data.find() ile hizli arama
    rtti_candidates = 0
    search_limit = min(len(data), 5_000_000)
    for tk_byte in (_TK_CLASS, _TK_CLASS_V2):
        pos = 0
        while pos < search_limit - 32:
            idx = data.find(bytes([tk_byte]), pos, search_limit)
            if idx == -1:
                break
            name_len = data[idx + 1] if idx + 1 < len(data) else 0
            if 3 <= name_len <= 128 and idx + 2 + name_len <= len(data):
                try:
                    name = data[idx + 2: idx + 2 + name_len].decode("ascii")
                    if re.match(r"^T[A-Z][A-Za-z0-9]+$", name):
                        rtti_candidates += 1
                        if rtti_candidates >= 3:
                            break
                except (UnicodeDecodeError, ValueError):
                    pass
            pos = idx + 1
        if rtti_candidates >= 3:
            break

    if rtti_candidates >= 3:
        result["rtti_found"] = True
        result["is_delphi"] = True
        result["evidence"].append(f"RTTI class info: {rtti_candidates} kayit")

    return result


def _extract_rtti_classes(data: bytes, max_classes: int = 300) -> list[dict]:
    """Binary veriden Delphi RTTI class bilgilerini cikar.

    RTTI yapisinda her class icin:
    - tkClass byte (0x07 veya 0x0D)
    - Class ismi (Pascal string: length byte + chars)
    - Class hiyerarsisi bilgisi (parent class pointer)

    Returns:
        list[dict]: name, parent (if detectable), methods (if any)
    """
    classes: list[dict] = []
    seen_names: set[str] = set()

    for tk_byte in (_TK_CLASS, _TK_CLASS_V2):
        offset = 0
        while offset < len(data) - 32 and len(classes) < max_classes:
            idx = data.find(bytes([tk_byte]), offset)
            if idx == -1:
                break

            name_len = data[idx + 1] if idx + 1 < len(data) else 0
            if 3 <= name_len <= 128 and idx + 2 + name_len <= len(data):
                name_bytes = data[idx + 2: idx + 2 + name_len]
                try:
                    name = name_bytes.decode("ascii")
                    if re.match(r"^T[A-Z][A-Za-z0-9_]+$", name) and name not in seen_names:
                        seen_names.add(name)
                        entry: dict[str, Any] = {
                            "name": name,
                            "offset": idx,
                            "is_vcl": name in _KNOWN_DELPHI_CLASSES,
                        }

                        # Parent class tespiti: RTTI'da class isminden sonra
                        # parent class pointer veya ismi gelebilir
                        # Basitlestirilmis: sonraki 32 byte'ta baska class ismi ara
                        after = data[idx + 2 + name_len: idx + 2 + name_len + 64]
                        for sub_offset in range(len(after) - 3):
                            sub_len = after[sub_offset]
                            if 3 <= sub_len <= 64 and sub_offset + 1 + sub_len <= len(after):
                                try:
                                    parent = after[sub_offset + 1: sub_offset + 1 + sub_len].decode("ascii")
                                    if re.match(r"^T[A-Z][A-Za-z0-9_]+$", parent):
                                        entry["parent"] = parent
                                        break
                                except (UnicodeDecodeError, ValueError):
                                    pass

                        classes.append(entry)
                except (UnicodeDecodeError, ValueError):
                    pass

            offset = idx + 1

    return classes


def _extract_dfm_resources(data: bytes, max_forms: int = 50) -> list[dict]:
    """Binary veriden DFM (Delphi Form Module) kaynaklarini cikar.

    DFM iki formatta olabilir:
    1. Text format: "object FormName: TFormClass" ile baslar
    2. Binary format: TPF0 magic ile baslar

    Returns:
        list[dict]: form_name, form_class, components (list)
    """
    forms: list[dict] = []

    # 1. Binary DFM (TPF0)
    offset = 0
    while offset < len(data) - 8 and len(forms) < max_forms:
        idx = data.find(_DFM_BIN_MAGIC_TPF0, offset)
        if idx == -1:
            break

        try:
            form_info = _parse_dfm_binary(data, idx)
            if form_info:
                forms.append(form_info)
        except (struct.error, IndexError, ValueError):
            pass

        offset = idx + 4

    # 2. Text DFM (PE resource'larda embedded olabilir)
    text_offset = 0
    while text_offset < len(data) - 20 and len(forms) < max_forms:
        idx = data.find(_DFM_TEXT_MAGIC, text_offset)
        if idx == -1:
            break

        try:
            # "object Name: TClassName" pattern
            line_end = data.find(b"\n", idx, idx + 200)
            if line_end == -1:
                line_end = min(idx + 200, len(data))
            line = data[idx:line_end].decode("ascii", errors="replace").strip()
            match = re.match(r"object\s+(\w+)\s*:\s*(T\w+)", line)
            if match:
                form_name = match.group(1)
                form_class = match.group(2)
                # Duplicate kontrolu
                if not any(f.get("form_name") == form_name for f in forms):
                    forms.append({
                        "form_name": form_name,
                        "form_class": form_class,
                        "format": "text",
                        "offset": idx,
                        "components": [],
                    })
        except (UnicodeDecodeError, ValueError):
            pass

        text_offset = idx + 7

    return forms


def _parse_dfm_binary(data: bytes, start: int) -> dict | None:
    """TPF0 binary DFM formatini parse et.

    TPF0 + class_name_len(1) + class_name + component_name_len(1) + component_name + properties...

    Returns:
        dict or None: form_name, form_class, format, components
    """
    pos = start + 4  # Skip TPF0

    if pos >= len(data):
        return None

    # Class name (Pascal string)
    cls_len = data[pos]
    pos += 1
    if cls_len == 0 or pos + cls_len > len(data):
        return None

    try:
        form_class = data[pos:pos + cls_len].decode("ascii")
    except UnicodeDecodeError:
        return None
    pos += cls_len

    # Component name (Pascal string)
    if pos >= len(data):
        return None
    name_len = data[pos]
    pos += 1
    if name_len == 0 or pos + name_len > len(data):
        return None

    try:
        form_name = data[pos:pos + name_len].decode("ascii")
    except UnicodeDecodeError:
        return None
    pos += name_len

    # Validate: class ismi T ile baslamali
    if not form_class.startswith("T"):
        return None

    # Child component'leri cikar (basitlestirilmis)
    components: list[str] = []
    search_end = min(pos + 4096, len(data))  # Max 4KB icinde ara
    sub_data = data[pos:search_end]

    # Child component pattern: class_len + class_name + name_len + name
    sub_offset = 0
    while sub_offset < len(sub_data) - 4 and len(components) < 100:
        c_len = sub_data[sub_offset]
        if 3 <= c_len <= 64 and sub_offset + 1 + c_len < len(sub_data):
            try:
                c_name = sub_data[sub_offset + 1: sub_offset + 1 + c_len].decode("ascii")
                if re.match(r"^T[A-Z][A-Za-z0-9]+$", c_name):
                    # Component ismi hemen arkasindan gelebilir
                    n_pos = sub_offset + 1 + c_len
                    if n_pos < len(sub_data):
                        n_len = sub_data[n_pos]
                        if 1 <= n_len <= 64 and n_pos + 1 + n_len <= len(sub_data):
                            try:
                                comp_name = sub_data[n_pos + 1: n_pos + 1 + n_len].decode("ascii")
                                if re.match(r"^[A-Za-z_]\w*$", comp_name):
                                    components.append(f"{comp_name}: {c_name}")
                            except UnicodeDecodeError:
                                pass
            except UnicodeDecodeError:
                pass
        sub_offset += 1

    return {
        "form_name": form_name,
        "form_class": form_class,
        "format": "binary",
        "offset": start,
        "components": components[:50],
    }


def _extract_vmt_info(data: bytes) -> dict[str, Any]:
    """Virtual Method Table (VMT) bilgilerini cikar.

    Delphi VMT yapisi (basitlestirilmis):
    - VMT pointer -> class ismi, parent VMT pointer, method table
    - Mangled symbol'lerden class hiyerarsisi cikarilabilir

    Returns:
        dict: class_hierarchy, virtual_method_count, vmt_entries
    """
    result: dict[str, Any] = {
        "class_hierarchy": [],
        "virtual_method_count": 0,
        "mangled_symbols": [],
    }

    # Delphi mangled name pattern: @Unit@Class@Method$qqr...
    mangled = re.findall(
        rb"@([A-Z][A-Za-z0-9_]{2,})@([A-Z][A-Za-z0-9_]{2,})@([A-Za-z_][A-Za-z0-9_]*)\$qqr",
        data[:5_000_000],
    )

    # Unit.Class.Method grupla
    class_methods: dict[str, dict[str, list[str]]] = {}
    for unit, cls, method in mangled:
        unit_s = unit.decode("ascii", errors="replace")
        cls_s = cls.decode("ascii", errors="replace")
        method_s = method.decode("ascii", errors="replace")
        key = f"{unit_s}.{cls_s}"
        if key not in class_methods:
            class_methods[key] = {"unit": unit_s, "class": cls_s, "methods": []}
        if method_s not in class_methods[key]["methods"]:
            class_methods[key]["methods"].append(method_s)

    result["mangled_symbols"] = [
        {
            "full_name": k,
            "unit": v["unit"],
            "class": v["class"],
            "methods": v["methods"][:50],
            "method_count": len(v["methods"]),
        }
        for k, v in sorted(class_methods.items())
    ][:200]

    result["virtual_method_count"] = sum(
        len(v["methods"]) for v in class_methods.values()
    )

    # Class hiyerarsisi: bilinen VCL class'larindan cikar
    for entry in result["mangled_symbols"]:
        cls_name = entry["class"]
        if cls_name.startswith("T"):
            result["class_hierarchy"].append(cls_name)

    return result


def _detect_compiler_version(data: bytes) -> dict[str, Any]:
    """Delphi compiler versiyonunu tespit et.

    PE resource'lardan ve string pattern'lerden versiyon bilgisi cikarir.

    Returns:
        dict: version_string, version_label, linker_version
    """
    result: dict[str, Any] = {
        "version_string": None,
        "version_label": None,
        "linker_version": None,
    }

    text = data[:2_000_000].decode("ascii", errors="replace")

    # Spesifik versiyon string'leri
    for full_ver, label in _DELPHI_VERSION_MAP.items():
        if full_ver in text:
            result["version_string"] = full_ver
            result["version_label"] = label
            break

    if not result["version_string"]:
        for marker in _DELPHI_COMPILER_STRINGS:
            if marker in text:
                result["version_string"] = marker
                break

    # PE linker version (offset 0x40-0x4F)
    if len(data) > 0x60:
        try:
            # PE optional header linker version
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            if pe_offset + 28 < len(data) and data[pe_offset:pe_offset + 4] == _PE_SIGNATURE:
                # COFF header (20 bytes) + optional header
                opt_start = pe_offset + 24
                linker_major = data[opt_start + 2]
                linker_minor = data[opt_start + 3]
                result["linker_version"] = f"{linker_major}.{linker_minor}"
                # Delphi linker version'lari: 2.25 (D7), 6.0 (DXE+), vb.
                if linker_major == 2 and linker_minor == 25:
                    result["version_label"] = result.get("version_label") or "Delphi 7 (linker 2.25)"
        except (struct.error, IndexError):
            pass

    return result


@register_analyzer(TargetType.DELPHI_BINARY)
class DelphiBinaryAnalyzer(BaseAnalyzer):
    """Delphi (Object Pascal) binary analiz motoru.

    PE binary'den Delphi RTTI, DFM form kaynaklari, VMT bilgileri
    ve compiler versiyon tespiti yapar.
    """

    supported_types = [TargetType.DELPHI_BINARY]

    def __init__(self, config: Config) -> None:
        super().__init__(config)

    @staticmethod
    def can_handle(target_info: TargetInfo) -> bool:
        """Delphi binary mi kontrol et.

        PE formati + Delphi runtime string'leri/RTTI pattern'leri aranir.
        """
        path = target_info.path
        suffix = path.suffix.lower()

        if suffix not in (".exe", ".dll", ".bpl", ".dcp"):
            return False

        try:
            with open(path, "rb") as f:
                # PE magic
                if f.read(2) != _PE_MAGIC:
                    return False
                # Ilk 512KB'da Delphi marker'lari ara
                data = f.read(524_288)

            detection = _detect_delphi_binary(data)
            return detection["is_delphi"]
        except (OSError, PermissionError):
            return False

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Delphi binary statik analiz.

        Analiz adimlari:
        1. Delphi detection (compiler, versiyon)
        2. RTTI class extraction
        3. DFM form resource extraction
        4. VMT traversal (mangled symbols)
        5. Package/unit tespiti
        """
        start = time.monotonic()
        result_data: dict[str, Any] = {}
        errors: list[str] = []

        try:
            raw_data = target.path.read_bytes()
        except OSError as e:
            errors.append(f"Dosya okunamadi: {e}")
            raw_data = b""

        # 1. Delphi detection ve compiler version
        detection = _detect_delphi_binary(raw_data)
        result_data["detection"] = detection

        compiler_info = _detect_compiler_version(raw_data)
        result_data["compiler"] = compiler_info

        # 2. RTTI class extraction
        rtti_classes = _extract_rtti_classes(raw_data)
        result_data["rtti_classes"] = rtti_classes

        # 3. DFM form extraction
        dfm_forms = _extract_dfm_resources(raw_data)
        result_data["dfm_forms"] = dfm_forms

        # 4. VMT traversal
        vmt_info = _extract_vmt_info(raw_data)
        result_data["vmt_info"] = {
            "class_hierarchy": vmt_info["class_hierarchy"][:100],
            "virtual_method_count": vmt_info["virtual_method_count"],
            "mangled_symbols": vmt_info["mangled_symbols"][:100],
        }

        # 5. Unit/Package tespiti (string'lerden)
        units = self._detect_units(raw_data)
        result_data["units"] = units

        # Kaydet
        output_path = workspace.get_stage_dir("static") / "delphi_analysis.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result_data, indent=2, default=str))

        # Istatistikler
        stats = {
            "rtti_classes": len(rtti_classes),
            "dfm_forms": len(dfm_forms),
            "mangled_symbols": len(vmt_info.get("mangled_symbols", [])),
            "virtual_methods": vmt_info.get("virtual_method_count", 0),
            "compiler_version": compiler_info.get("version_label")
            or compiler_info.get("version_string"),
            "units": len(units),
        }

        duration = time.monotonic() - start
        return StageResult(
            stage_name="static",
            success=True,
            duration_seconds=duration,
            artifacts={"delphi_analysis": str(output_path)},
            stats=stats,
            errors=errors,
        )

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Delphi deobfuscation -- su an sadece placeholder.

        Delphi binary'lerde obfuscation nadir gorulur.
        VMT patching ve string encryption cilebilir.
        """
        return StageResult(
            stage_name="deobfuscate", success=True, duration_seconds=0.0,
            artifacts={}, stats={}, errors=[],
        )

    def reconstruct(self, target: TargetInfo, workspace: Workspace) -> StageResult | None:
        """Delphi proje yapisi olustur.

        RTTI ve DFM bilgilerinden .dpr/.pas/.dfm dosyalari olusturur.
        """
        start = time.monotonic()
        output_dir = workspace.get_stage_dir("reconstructed") / "delphi_project"
        output_dir.mkdir(parents=True, exist_ok=True)

        analysis_path = workspace.get_stage_dir("static") / "delphi_analysis.json"
        if not analysis_path.exists():
            return None

        analysis = json.loads(analysis_path.read_text())
        project_name = target.name or "DelphiProject"

        # .dpr (project file) olustur
        dpr_content = self._generate_dpr(project_name, analysis)
        (output_dir / f"{project_name}.dpr").write_text(dpr_content)

        # DFM form'lari icin stub .pas ve .dfm dosyalari
        dfm_forms = analysis.get("dfm_forms", [])
        for form in dfm_forms:
            form_name = form.get("form_name", "")
            form_class = form.get("form_class", "TForm")
            if form_name:
                # .pas stub
                pas_content = self._generate_form_unit(form_name, form_class, form)
                (output_dir / f"{form_name}.pas").write_text(pas_content)

        return StageResult(
            stage_name="reconstruct", success=True,
            duration_seconds=time.monotonic() - start,
            artifacts={"delphi_project": str(output_dir)},
            stats={"reconstructed": True, "forms_generated": len(dfm_forms)},
            errors=[],
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_units(data: bytes) -> list[str]:
        """Delphi unit isimlerini string'lerden cikar.

        Delphi unit isimleri genellikle "UnitName.pas" veya
        mangled name'lerde @UnitName@ olarak bulunur.
        """
        units: set[str] = set()

        # @UnitName@ pattern'leri
        mangled_units = re.findall(
            rb"@([A-Z][A-Za-z0-9_]{2,50})@[A-Z]",
            data[:3_000_000],
        )
        for u in mangled_units:
            name = u.decode("ascii", errors="replace")
            # System/SysUtils gibi standart unit'leri de ekle
            units.add(name)

        # ".pas" referanslari
        pas_refs = re.findall(
            rb"([A-Z][A-Za-z0-9_]{2,50})\.pas",
            data[:3_000_000],
        )
        for p in pas_refs:
            units.add(p.decode("ascii", errors="replace"))

        return sorted(units)[:200]

    @staticmethod
    def _generate_dpr(name: str, analysis: dict) -> str:
        """Delphi project (.dpr) dosyasi olustur."""
        units = analysis.get("units", [])
        forms = analysis.get("dfm_forms", [])

        uses_list = []
        for form in forms:
            fn = form.get("form_name", "")
            if fn:
                uses_list.append(f"  {fn} in '{fn}.pas'")

        uses_block = ",\n".join(uses_list) if uses_list else "  // (bilinmiyor)"

        compiler = analysis.get("compiler", {})
        version_info = compiler.get("version_label") or compiler.get("version_string") or "bilinmiyor"

        return f"""// Karadul v1.0 tarafindan olusturuldu (RTTI + DFM'den reconstruct)
// Orijinal Delphi versiyonu: {version_info}
// Tespit edilen {len(units)} unit, {len(forms)} form

program {name};

uses
  Forms,
{uses_block};

{{$R *.res}}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  // Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
"""

    @staticmethod
    def _generate_form_unit(form_name: str, form_class: str,
                            form_data: dict) -> str:
        """Delphi form unit (.pas) stub olustur."""
        components = form_data.get("components", [])
        comp_declarations = "\n".join(
            f"    {c};" for c in components[:30]
        ) if components else "    // (component'ler tespit edilemedi)"

        return f"""// Karadul v1.0 tarafindan olusturuldu (DFM'den reconstruct)
unit {form_name};

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ExtCtrls, ComCtrls;

type
  {form_class} = class(TForm)
{comp_declarations}
  private
    {{ Private declarations }}
  public
    {{ Public declarations }}
  end;

var
  {form_name}: {form_class};

implementation

{{$R *.dfm}}

end.
"""
