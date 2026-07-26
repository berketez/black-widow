"""Python packed binary analyzer.

PyInstaller, cx_Freeze, Nuitka ile paketlenmis Python uygulamalarini analiz eder:
- PyInstaller: PYZ magic bytes, MEIPASS marker, PKG/TOC yapisi
- cx_Freeze: frozen module detection, cx_Freeze marker strings
- Nuitka: nuitka-version string, _nuitka marker
- Python versiyonu tespiti (.pyc magic number'dan)
- Embedded .pyc dosyalarinin listesini cikarma

Strateji:
1. Magic bytes ve string pattern'lerle paketleyici tespit et
2. Binary icindeki .pyc referanslarini bul
3. Python versiyonu tespit et (.pyc magic -> versiyon eslesmesi)
4. Embedded modul listesini cikar
"""

from __future__ import annotations

import json
import logging
import re
import struct
import time
from pathlib import Path
from typing import Any

from karadul.analyzers import register_analyzer
from karadul.analyzers.base import BaseAnalyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.subprocess_runner import SubprocessRunner
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.analyzers.pyc_decompiler import (
    _PYC_MAGIC_TO_VERSION,
    decompile_pyc,
    repair_pyc_header,
    version_from_pyc_bytes,
)

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# PyInstaller magic bytes & markers
# --------------------------------------------------------------------------

# PyInstaller archive cookie (end-of-archive marker)
# "MEI\014\013\012\013\016" — 8 byte magic
_PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"

# PyInstaller bootloader MEIPASS marker
_MEIPASS_MARKER = b"_MEIPASS"

# PYZ archive magic bytes (used inside PyInstaller archives)
# "PYZ\0" header
_PYZ_MAGIC = b"PYZ\x00"

# --------------------------------------------------------------------------
# cx_Freeze markers
# --------------------------------------------------------------------------

_CXFREEZE_MARKERS = [
    b"cx_Freeze",
    b"cx_freeze",
    b"__cxfreeze__",
    b"frozen_modules",
    b"initscript",
]

# --------------------------------------------------------------------------
# Nuitka markers
# --------------------------------------------------------------------------

_NUITKA_MARKERS = [
    b"nuitka-version:",
    b"Nuitka",
    b"_nuitka",
    b"__nuitka_binary",
    b"onefile_bootstrap",
]

# --------------------------------------------------------------------------
# .pyc magic number -> Python versiyon tablosu artik pyc_decompiler.py'de
# TEK KAYNAK (CLAUDE.md #11). Yukarida import edildi; re-export burada tutulur
# (geriye donuk: bu modulden import eden kod calismaya devam eder).

# Python versiyon string pattern'leri (binary string'lerde)
_PYTHON_VERSION_PATTERN = re.compile(
    r"Python\s+(\d+\.\d+(?:\.\d+)?)"
)
_PYTHON_VERSION_SHORT_PATTERN = re.compile(
    r"python(\d)\.(\d{1,2})"
)

# .pyc/.pyo dosya referans pattern'i (embedded modullerin isimleri)
_PYC_MODULE_PATTERN = re.compile(
    r"([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\.pyc?"
)


def _pyinstaller_note(summary: dict[str, Any]) -> str:
    """PyInstaller manifest notu -- decompile sonucuna gore dinamik ve DURUST.

    "Python %100" iddia edilmez; ne decompile edildi, ne disassembly'de kaldi
    acikca yazilir (bkz. pyc_decompiler bilgisel tavan notu).
    """
    if not summary or summary.get("total_pyc", 0) == 0:
        return (
            "PyInstaller CArchive acildi; extracted/ altinda dosyalar var ama "
            ".pyc bulunamadi (native .so veya sifreli olabilir)."
        )
    total = summary.get("total_pyc", 0)
    dec = summary.get("decompiled", 0)
    dis = summary.get("disasm", 0)
    failed = summary.get("failed", 0)
    parts = [f"{total} .pyc islendi"]
    if dec:
        parts.append(f"{dec} tanesi kaynak (.py) olarak decompile edildi")
    if dis:
        parts.append(
            f"{dis} tanesi yalniz bytecode disassembly olarak kurtarildi "
            "(daha iyi sonuc icin pycdc kurun: scripts/setup_pycdc.sh)"
        )
    if failed:
        parts.append(f"{failed} tanesi cozulemedi")
    return "; ".join(parts) + "."


@register_analyzer(TargetType.PYTHON_PACKED)
class PythonBinaryAnalyzer(BaseAnalyzer):
    """Python packed binary analyzer.

    PyInstaller, cx_Freeze, Nuitka ile paketlenmis Python
    uygulamalarini analiz eder. Paketleyici tespiti, Python
    versiyon tespiti ve embedded modul listesini cikarir.
    """

    supported_types = [TargetType.PYTHON_PACKED]

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.runner = SubprocessRunner(config)

    # ------------------------------------------------------------------
    # Public interface (BaseAnalyzer)
    # ------------------------------------------------------------------

    @staticmethod
    def can_handle(target_info: TargetInfo) -> bool:
        """Python packed binary mi kontrol et.

        Binary icindeki PyInstaller, cx_Freeze veya Nuitka
        marker'larina bakar.
        """
        try:
            with open(target_info.path, "rb") as f:
                data = f.read(2 * 1024 * 1024)  # Ilk 2MB
        except OSError:
            return False

        # PyInstaller: MEIPASS marker veya MEI magic
        if _MEIPASS_MARKER in data:
            return True
        if _PYINSTALLER_MAGIC in data:
            return True
        if _PYZ_MAGIC in data:
            return True

        # cx_Freeze markers
        for marker in _CXFREEZE_MARKERS:
            if marker in data:
                return True

        # Nuitka markers
        for marker in _NUITKA_MARKERS:
            if marker in data:
                return True

        return False

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Python packed binary statik analizi.

        Siralama:
        1. Paketleyici tipi tespiti (PyInstaller/cx_Freeze/Nuitka)
        2. Python versiyon tespiti
        3. Embedded .pyc modul listesi cikarma
        4. PyInstaller TOC (Table of Contents) parse
        5. String extraction

        Args:
            target: Hedef bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Statik analiz sonucu.
        """
        start = time.monotonic()
        artifacts: dict[str, Path] = {}
        errors: list[str] = []
        stats: dict[str, Any] = {
            "analyzer": "python_binary",
        }

        binary_path = target.path

        # Binary verisini oku (analiz boyunca kullanilacak)
        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()
        except OSError as exc:
            errors.append(f"Binary okunamadi: {exc}")
            return StageResult(
                stage_name="static",
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=errors,
            )

        # 1. Paketleyici tespiti
        packer_info = self._detect_packer(binary_data)
        stats["packer"] = packer_info["packer"]
        stats["packer_confidence"] = packer_info["confidence"]
        if packer_info.get("details"):
            packer_path = workspace.save_json("static", "python_packer", packer_info)
            artifacts["python_packer"] = packer_path

        # 2. Python versiyon tespiti
        python_version = self._detect_python_version(binary_data)
        stats["python_version"] = python_version or "unknown"
        # reconstruct icin sakla: PyInstaller .pyc header'lari genelde SIYRILMIS oldugundan
        # decompile asamasi surumu buradan ogrenir (header'dan okuyamaz).
        if python_version:
            workspace.save_json("static", "python_version", {"version": python_version})

        # 3. Embedded .pyc modulleri
        modules = self._extract_embedded_modules(binary_data)
        if modules:
            mod_path = workspace.save_json("static", "python_modules", modules)
            artifacts["python_modules"] = mod_path
            stats["module_count"] = modules["total"]
            stats["stdlib_modules"] = modules.get("stdlib_count", 0)
            stats["user_modules"] = modules.get("user_count", 0)

        # "Functions recovered" (cli.py) proxy'si: kurtarilan Python modul sayisi.
        # JVM'de metot, .NET'te CIL metodu; Python'da modul = kurtarilan kod birimi.
        # Set edilmezse packed binary "0 fonksiyon" gorunur (kapsam bug'i, misroute deseni).
        _recovered_modules = stats.get("module_count", 0)
        stats["functions"] = _recovered_modules
        stats["functions_found"] = _recovered_modules

        # 4. PyInstaller TOC (varsa)
        if packer_info["packer"] == "pyinstaller":
            toc = self._parse_pyinstaller_toc(binary_data)
            if toc:
                toc_path = workspace.save_json("static", "pyinstaller_toc", toc)
                artifacts["pyinstaller_toc"] = toc_path
                stats["toc_entry_count"] = toc.get("total", 0)

        # 5. String extraction
        string_list = self.runner.run_strings(binary_path)
        if string_list:
            # Python-ilgili stringleri filtrele
            py_strings = self._filter_python_strings(string_list)
            strings_data = {
                "total": len(string_list),
                "python_related": len(py_strings),
                "strings": string_list[:10000],
                "python_strings": py_strings[:2000],
            }
            str_path = workspace.save_json("static", "strings_raw", strings_data)
            artifacts["strings_raw"] = str_path
            stats["string_count"] = len(string_list)
            stats["python_string_count"] = len(py_strings)

        duration = time.monotonic() - start
        stats["total_duration"] = round(duration, 3)

        return StageResult(
            stage_name="static",
            success=packer_info["packer"] != "unknown" or len(artifacts) > 0,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Python packed binary deobfuscation.

        Python packed binary'ler icin deobfuscation:
        - Modul listesini deobfuscated dizinine tasi
        - Packer bilgisini raporla
        """
        start = time.monotonic()
        artifacts: dict[str, Path] = {}
        errors: list[str] = []

        # Packer bilgisini tasi
        packer_info = workspace.load_json("static", "python_packer")
        if packer_info:
            deobf_path = workspace.save_json("deobfuscated", "python_packer", packer_info)
            artifacts["python_packer"] = deobf_path

        # Modul listesini tasi
        modules = workspace.load_json("static", "python_modules")
        if modules:
            mod_path = workspace.save_json("deobfuscated", "python_modules", modules)
            artifacts["python_modules"] = mod_path
        else:
            errors.append("Embedded modul listesi bulunamadi")

        return StageResult(
            stage_name="deobfuscate",
            success=len(errors) == 0 or len(artifacts) > 0,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            errors=errors,
        )

    def reconstruct(self, target: TargetInfo, workspace: Workspace) -> StageResult | None:
        """Python paketinden proje iskeleti olustur.

        Native binary DEGIL: Ghidra/JS yerine paketleyiciye ozel kurtarma. PyInstaller
        icin `packed_binary.PyInstallerExtractor` ile GERCEK CArchive extraction yapilir
        (pipeline'a bagli olmayan gercek unpacker'i burada wire eder) -> cikarilmis
        .pyc/.py dosyalari + manifest. Static analiz kosmadiysa (packer/modul JSON'u yok)
        None doner -> ReconstructionStage bunu graceful fail'e cevirir.

        Ciktı: reconstructed/python_project/ (extracted/ + manifest.json).
        """
        start = time.monotonic()

        # Static analiz kosmus olmali (packer + modul bilgisi icin)
        packer_info = workspace.load_json("static", "python_packer")
        modules = workspace.load_json("static", "python_modules")
        if not packer_info and not modules:
            return None

        output_dir = workspace.get_stage_dir("reconstructed") / "python_project"
        output_dir.mkdir(parents=True, exist_ok=True)

        packer = (packer_info or {}).get("packer", "unknown")
        extracted_count = 0
        extract_errors: list[str] = []
        decompile_summary: dict[str, Any] = {}

        # PyInstaller: gercek CArchive extraction (packed_binary unpacker'i wire et)
        if packer == "pyinstaller":
            try:
                from karadul.analyzers.packed_binary import PyInstallerExtractor
                unpack = PyInstallerExtractor(self.config).extract(
                    target.path, output_dir / "extracted",
                )
                extracted_count = len(unpack.extracted_files)
                extract_errors = list(unpack.errors)
                # .pyc -> .py: header onar + deterministik decompile (LLM'siz zincir).
                # Surum static asamada tespit edildi (PyInstaller header'lari siyrilmis olur).
                pv_info = workspace.load_json("static", "python_version")
                detected_version = (pv_info or {}).get("version")
                decompile_summary = self._decompile_pyc_files(
                    unpack.extracted_files, output_dir, py_version=detected_version,
                )
            except Exception as exc:
                logger.debug("PyInstaller extraction basarisiz: %s", exc, exc_info=True)
                extract_errors.append(f"{type(exc).__name__}: {exc}")

        # Manifest: kurtarilan yapinin ozeti (extraction basarisiz olsa da yazilir)
        manifest = {
            "packer": packer,
            "native_format": target.metadata.get("native_format"),
            "module_summary": {
                "total": (modules or {}).get("total", 0),
                "user": (modules or {}).get("user_count", 0),
                "stdlib": (modules or {}).get("stdlib_count", 0),
            },
            "extracted_count": extracted_count,
            "decompile": decompile_summary,
            "extraction_errors": extract_errors,
            "note": (
                _pyinstaller_note(decompile_summary)
                if packer == "pyinstaller" else
                f"Paketleyici '{packer}': tam extraction yalnizca PyInstaller icin destekli."
            ),
        }
        (output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, default=str)
        )

        return StageResult(
            stage_name="reconstruct",
            success=True,
            duration_seconds=time.monotonic() - start,
            artifacts={"python_project": output_dir},
            stats={
                "reconstructed": True,
                "extracted_count": extracted_count,
                "decompiled_count": decompile_summary.get("decompiled", 0),
                "disasm_count": decompile_summary.get("disasm", 0),
            },
            errors=extract_errors,
        )

    def _decompile_pyc_files(
        self, extracted_files: list, output_dir: Path,
        py_version: str | None = None,
    ) -> dict[str, Any]:
        """Extract edilmis .pyc'leri header-onar + deterministik decompile.

        Cikti: ``output_dir/source/`` altina ``.py`` (basari) veya
        ``.disasm.txt`` (kismi kurtarma). Zincir: pycdc -> decompyle3/uncompyle6
        -> disassembly (bkz. pyc_decompiler). LLM/ML KULLANILMAZ.

        Args:
            extracted_files: PyInstallerExtractor ciktisi (ExtractedFile listesi).
            output_dir: reconstructed/python_project dizini.
            py_version: Static asamada tespit edilen Python surumu. PyInstaller
                .pyc header'larini siyirdigi icin surum genelde .pyc'den okunamaz;
                header onarimi bu degere dayanir.

        Returns:
            Ozet dict: total_pyc, decompiled, disasm, failed, methods{}.
        """
        pyc_files = [
            ef for ef in extracted_files
            if getattr(ef, "file_type", "") == "pyc" and ef.path.exists()
        ]
        summary: dict[str, Any] = {
            "total_pyc": len(pyc_files),
            "decompiled": 0,
            "disasm": 0,
            "failed": 0,
            "methods": {},
        }
        if not pyc_files:
            return summary

        source_dir = output_dir / "source"
        source_dir.mkdir(parents=True, exist_ok=True)

        # Global surum: once header tasiyan bir .pyc'den oku; hicbiri header tasimiyorsa
        # (PyInstaller tipik olarak siyirir) static asamada tespit edilen surume dus.
        global_version: str | None = None
        for ef in pyc_files:
            try:
                v = version_from_pyc_bytes(ef.path.read_bytes())
            except OSError:
                v = None
            if v:
                global_version = v
                break
        if global_version is None:
            global_version = py_version

        # pycdc icin vendor/pycdc dizinini extra_paths olarak ekle (setup_pycdc.sh buraya kurar).
        vendor_pycdc = Path(__file__).resolve().parents[2] / "vendor" / "pycdc"
        extra = [str(vendor_pycdc)] if vendor_pycdc.is_dir() else None
        timeout = float(getattr(self.config.timeouts, "subprocess", 120.0))

        for ef in pyc_files:
            try:
                body = ef.path.read_bytes()
            except OSError:
                summary["failed"] += 1
                continue

            repaired = repair_pyc_header(body, global_version)
            if repaired is not None and repaired != body:
                # Header onarildi -> onarilmis kopyayi diske yaz, onu decompile et.
                fixed = ef.path.with_suffix(".fixed.pyc")
                try:
                    fixed.write_bytes(repaired)
                    target_pyc = fixed
                except OSError:
                    target_pyc = ef.path
            else:
                target_pyc = ef.path

            res = decompile_pyc(
                target_pyc, source_dir,
                py_version=global_version, timeout=timeout, extra_paths=extra,
            )
            summary["methods"][res.method] = summary["methods"].get(res.method, 0) + 1
            if res.success:
                summary["decompiled"] += 1
            elif res.is_disassembly:
                summary["disasm"] += 1
            else:
                summary["failed"] += 1

        return summary

    # ------------------------------------------------------------------
    # Packer detection
    # ------------------------------------------------------------------

    def _detect_packer(self, data: bytes) -> dict[str, Any]:
        """Paketleyici tipini tespit et.

        Binary verisi icindeki magic byte ve marker string'lerle
        PyInstaller, cx_Freeze veya Nuitka tespiti yapar.

        Returns:
            dict: packer (str), confidence (str), details (dict)
        """
        details: dict[str, Any] = {}
        scores: dict[str, int] = {
            "pyinstaller": 0,
            "cx_freeze": 0,
            "nuitka": 0,
        }

        # --- PyInstaller ---
        if _PYINSTALLER_MAGIC in data:
            scores["pyinstaller"] += 3
            details["pyinstaller_magic"] = True

        if _MEIPASS_MARKER in data:
            scores["pyinstaller"] += 3
            details["meipass_marker"] = True

        if _PYZ_MAGIC in data:
            scores["pyinstaller"] += 2
            details["pyz_magic"] = True

        # PyInstaller bootloader string'leri
        pyinstaller_strings = [
            b"pyi-runtime",
            b"_pyi_main_co",
            b"PYTHONINSPECT",
            b"_PYI_PROCNAME",
        ]
        for marker in pyinstaller_strings:
            if marker in data:
                scores["pyinstaller"] += 1
                details.setdefault("pyinstaller_strings", []).append(
                    marker.decode("ascii", errors="replace")
                )

        # --- cx_Freeze ---
        for marker in _CXFREEZE_MARKERS:
            if marker in data:
                scores["cx_freeze"] += 2
                details.setdefault("cx_freeze_markers", []).append(
                    marker.decode("ascii", errors="replace")
                )

        # --- Nuitka ---
        for marker in _NUITKA_MARKERS:
            if marker in data:
                scores["nuitka"] += 2
                details.setdefault("nuitka_markers", []).append(
                    marker.decode("ascii", errors="replace")
                )

        # Nuitka-spesifik: compiled module pattern
        if b".cpython-" in data and b".so" in data:
            scores["nuitka"] += 1
        if b"__compiled__" in data:
            scores["nuitka"] += 2

        # En yuksek skoru sec
        max_packer = max(scores, key=lambda k: scores[k])
        max_score = scores[max_packer]

        if max_score == 0:
            return {"packer": "unknown", "confidence": "none", "details": {}}

        confidence = "low"
        if max_score >= 3:
            confidence = "medium"
        if max_score >= 5:
            confidence = "high"

        return {
            "packer": max_packer,
            "confidence": confidence,
            "scores": scores,
            "details": details,
        }

    # ------------------------------------------------------------------
    # Python version detection
    # ------------------------------------------------------------------

    def _detect_python_version(self, data: bytes) -> str | None:
        """Binary'den Python versiyonunu tespit et.

        Stratejiler:
        1. .pyc magic number'dan versiyon haritasi
        2. "Python X.Y.Z" string pattern'i
        3. "pythonX.Y" kisa format
        """
        # Strateji 1: .pyc magic number ara
        version = self._version_from_pyc_magic(data)
        if version:
            return version

        # Strateji 2: "Python X.Y.Z" string pattern
        text = data.decode("ascii", errors="replace")
        match = _PYTHON_VERSION_PATTERN.search(text)
        if match:
            return match.group(1)

        # Strateji 3: "pythonX.Y" (orn: "python3.11", "libpython3.10.so")
        match = _PYTHON_VERSION_SHORT_PATTERN.search(text)
        if match:
            return f"{match.group(1)}.{match.group(2)}"

        return None

    def _version_from_pyc_magic(self, data: bytes) -> str | None:
        """Binary icindeki .pyc magic number'lardan Python versiyonu bul.

        .pyc dosyalari 4-byte little-endian magic number ile baslar.
        Bu magic number Python surumune ozgudur.

        Binary icinde gomulu .pyc dosyalarinin magic number'larini
        arar ve bilinen versiyonlarla eslestirir.
        """
        # .pyc magic number pattern: 2-byte versiyon + \\r\\n (0x0D0A)
        # Ornek: Python 3.11 -> 0xa70d (little-endian) + 0x0d0a
        # Binary icinde \\r\\n\\r\\n pattern'i ara (pyc header)
        pyc_header_pattern = re.compile(rb"(..\r\n)")

        found_versions: dict[str, int] = {}

        for match in pyc_header_pattern.finditer(data):
            pos = match.start()
            if pos + 4 > len(data):
                continue

            # 2-byte little-endian magic number oku
            try:
                magic_num = struct.unpack("<H", data[pos:pos + 2])[0]
            except struct.error:
                continue

            version = _PYC_MAGIC_TO_VERSION.get(magic_num)
            if version:
                found_versions[version] = found_versions.get(version, 0) + 1

        if not found_versions:
            return None

        # En cok bulunan versiyon
        return max(found_versions, key=lambda k: found_versions[k])

    # ------------------------------------------------------------------
    # Embedded module extraction
    # ------------------------------------------------------------------

    def _extract_embedded_modules(self, data: bytes) -> dict[str, Any] | None:
        """Binary icindeki embedded Python modullerini cikar.

        .pyc dosya referanslarini ve modul isimlerini bulur.
        """
        text = data.decode("ascii", errors="replace")

        modules: list[dict[str, str]] = []
        seen: set[str] = set()

        # Python modulu olabilecek string'leri bul
        for match in _PYC_MODULE_PATTERN.finditer(text):
            module_name = match.group(1)

            # Cok kisa veya cok uzun isimleri filtrele
            if len(module_name) < 2 or len(module_name) > 200:
                continue

            # Zaten gorulmus mu
            if module_name in seen:
                continue
            seen.add(module_name)

            # False positive filtreleme
            # Buyuk harfle baslayan, sayi ile baslayan vb. filtrele
            if not module_name[0].isalpha() and module_name[0] != "_":
                continue

            is_stdlib = self._is_python_stdlib(module_name)

            modules.append({
                "name": module_name,
                "type": "stdlib" if is_stdlib else "user",
            })

        if not modules:
            return None

        stdlib_count = sum(1 for m in modules if m["type"] == "stdlib")
        user_count = len(modules) - stdlib_count

        return {
            "total": len(modules),
            "stdlib_count": stdlib_count,
            "user_count": user_count,
            "modules": modules[:5000],  # max 5000 modul
        }

    # ------------------------------------------------------------------
    # PyInstaller TOC parsing
    # ------------------------------------------------------------------

    def _parse_pyinstaller_toc(self, data: bytes) -> dict[str, Any] | None:
        """PyInstaller archive TOC (Table of Contents) parse.

        PyInstaller archive sonunda bir cookie (magic) bulunur.
        Cookie'den geriye dogru TOC offset'i okunur.

        Cookie format (son 24+ byte):
        - 8 byte: MEI magic
        - 4 byte: archive baslangic ofseti (length)
        - 4 byte: TOC offset
        - 4 byte: TOC length
        - 4 byte: Python versiyon (major * 100 + minor)
        """
        # MEI magic'i binary sonundan bul
        magic_pos = data.rfind(_PYINSTALLER_MAGIC)
        if magic_pos < 0:
            return None

        # Cookie'nin geri kalanini oku (magic'den sonra 16 byte)
        cookie_start = magic_pos
        if cookie_start + 24 > len(data):
            return None

        try:
            # Magic'den sonraki 16 byte'i parse et
            (pkg_length, toc_offset, toc_length, pyver) = struct.unpack(
                "<IIII", data[cookie_start + 8:cookie_start + 24]
            )
        except struct.error:
            return None

        # Versiyon decode: 311 -> "3.11"
        py_major = pyver // 100
        py_minor = pyver % 100
        py_version = f"{py_major}.{py_minor}" if pyver > 0 else None

        entries: list[dict[str, Any]] = []

        # TOC'u parse et
        # TOC entry format:
        # 4 byte: entry length (dahil)
        # 4 byte: compressed data offset
        # 4 byte: compressed data length
        # 4 byte: uncompressed data length
        # 1 byte: compress flag
        # 1 byte: type flag (s=script, m=module, M=package, z=PYZ, etc.)
        # variable: name (null-terminated)
        toc_abs_offset = cookie_start - pkg_length + toc_offset

        if 0 <= toc_abs_offset < len(data):
            pos = toc_abs_offset
            end = toc_abs_offset + toc_length

            while pos + 18 <= end and pos < len(data):
                try:
                    entry_len = struct.unpack("<I", data[pos:pos + 4])[0]
                except struct.error:
                    break

                if entry_len < 18 or entry_len > 65536:
                    break

                if pos + entry_len > len(data):
                    break

                try:
                    compress_flag = data[pos + 16]
                    type_flag = data[pos + 17]
                    # Isim: 18. byte'dan entry sonuna kadar, null-terminated
                    name_bytes = data[pos + 18:pos + entry_len]
                    null_idx = name_bytes.find(b"\x00")
                    if null_idx >= 0:
                        name_bytes = name_bytes[:null_idx]
                    name = name_bytes.decode("utf-8", errors="replace")
                except (IndexError, struct.error):
                    break

                type_char = chr(type_flag) if 32 <= type_flag < 127 else "?"
                entries.append({
                    "name": name,
                    "type": type_char,
                    "compressed": bool(compress_flag),
                })

                pos += entry_len

        if not entries and py_version is None:
            return None

        result: dict[str, Any] = {
            "total": len(entries),
            "entries": entries[:5000],
        }
        if py_version:
            result["python_version"] = py_version
        if pkg_length:
            result["package_length"] = pkg_length

        return result

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _is_python_stdlib(module_name: str) -> bool:
        """Python standart kutuphane modulu mu?"""
        top_level = module_name.split(".")[0]
        # Python 3.x stdlib top-level modulleri (kisaltilmis liste)
        stdlib_modules = {
            "abc", "aifc", "argparse", "array", "ast", "asynchat",
            "asyncio", "asyncore", "atexit", "audioop", "base64",
            "bdb", "binascii", "binhex", "bisect", "builtins",
            "bz2", "calendar", "cgi", "cgitb", "chunk", "cmath",
            "cmd", "code", "codecs", "codeop", "collections",
            "colorsys", "compileall", "concurrent", "configparser",
            "contextlib", "contextvars", "copy", "copyreg", "cProfile",
            "crypt", "csv", "ctypes", "curses", "dataclasses",
            "datetime", "dbm", "decimal", "difflib", "dis",
            "distutils", "doctest", "email", "encodings",
            "enum", "errno", "faulthandler", "fcntl", "filecmp",
            "fileinput", "fnmatch", "formatter", "fractions",
            "ftplib", "functools", "gc", "getopt", "getpass",
            "gettext", "glob", "grp", "gzip", "hashlib",
            "heapq", "hmac", "html", "http", "idlelib",
            "imaplib", "imghdr", "imp", "importlib", "inspect",
            "io", "ipaddress", "itertools", "json", "keyword",
            "lib2to3", "linecache", "locale", "logging", "lzma",
            "mailbox", "mailcap", "marshal", "math", "mimetypes",
            "mmap", "modulefinder", "multiprocessing", "netrc",
            "nis", "nntplib", "numbers", "operator", "optparse",
            "os", "ossaudiodev", "parser", "pathlib", "pdb",
            "pickle", "pickletools", "pipes", "pkgutil", "platform",
            "plistlib", "poplib", "posix", "posixpath", "pprint",
            "profile", "pstats", "pty", "pwd", "py_compile",
            "pyclbr", "pydoc", "queue", "quopri", "random",
            "re", "readline", "reprlib", "resource", "rlcompleter",
            "runpy", "sched", "secrets", "select", "selectors",
            "shelve", "shlex", "shutil", "signal", "site",
            "smtpd", "smtplib", "sndhdr", "socket", "socketserver",
            "sqlite3", "ssl", "stat", "statistics", "string",
            "stringprep", "struct", "subprocess", "sunau", "symtable",
            "sys", "sysconfig", "syslog", "tabnanny", "tarfile",
            "telnetlib", "tempfile", "termios", "test", "textwrap",
            "threading", "time", "timeit", "tkinter", "token",
            "tokenize", "tomllib", "trace", "traceback", "tracemalloc",
            "tty", "turtle", "turtledemo", "types", "typing",
            "unicodedata", "unittest", "urllib", "uu", "uuid",
            "venv", "warnings", "wave", "weakref", "webbrowser",
            "winreg", "winsound", "wsgiref", "xdrlib", "xml",
            "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
            # Python internal modulleri
            "_thread", "_io", "_abc", "_codecs", "_collections",
            "_functools", "_operator", "_signal", "_sre", "_stat",
            "_string", "_struct", "_warnings", "_weakref",
            "__future__", "_frozen_importlib",
        }
        return top_level in stdlib_modules

    @staticmethod
    def _filter_python_strings(strings: list[str]) -> list[str]:
        """String listesinden Python-ilgili olanlari filtrele."""
        python_indicators = [
            "import ", "from ", "def ", "class ",
            ".py", ".pyc", ".pyo", ".pyd",
            "Traceback", "Exception", "Error",
            "Python", "python", "PyObject",
            "__init__", "__main__", "__name__",
            "site-packages", "dist-packages",
            "pip", "setuptools", "pkg_resources",
            "MEIPASS", "PyInstaller", "cx_Freeze", "Nuitka",
        ]
        result = []
        for s in strings:
            if not isinstance(s, str):
                continue
            if any(indicator in s for indicator in python_indicators):
                result.append(s[:500])  # max 500 karakter
        return result
