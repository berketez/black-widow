"""Packed binary tespit ve acma modulu.

Paketlenmis binary'leri tespit edip acar:
- Entropy analizi ile packing tespiti
- UPX, PyInstaller, Nuitka tanima ve acma
- PyInstaller archive parse, TOC extraction, .pyc decompile
- Generic entropy-based section extraction

Config uyumlu: BinaryReconstructionConfig.enable_packed_detection
"""

from __future__ import annotations

import logging
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from karadul.config import Config
from karadul.core.safe_subprocess import resolve_tool, safe_run, safe_zlib_decompress

logger = logging.getLogger(__name__)


# v1.10.0 Batch 5B MED-11: Windows reserved file names.
# APK/PyInstaller icindeki "CON.txt", "PRN" gibi girdiler Windows host
# uzerinde device acilmasina sebep olur (veya crash). Case-insensitive
# karsilastirma icin buyuk harfe cevrilmis set.
_WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})


def _is_windows_reserved(name: str) -> bool:
    """Path'in herhangi bir bileseni Windows reserved name mi?"""
    # Path separator normalize
    parts = name.replace("\\", "/").split("/")
    for p in parts:
        stem = p.split(".")[0].upper().strip()
        if stem in _WINDOWS_RESERVED_NAMES:
            return True
    return False


# v1.10.0 Batch 5B CRITICAL-3: PyInstaller zlib decompress limit (100MB).
# staticmethod _extract_entry icinde self.config erisemiyor; modul sabit.
_MAX_PYINSTALLER_DECOMPRESS = 100 * 1024 * 1024


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class PackingType(Enum):
    """Packing turleri."""
    NONE = "none"
    UPX = "upx"
    PYINSTALLER = "pyinstaller"
    NUITKA = "nuitka"
    GENERIC_PACKED = "generic_packed"
    UNKNOWN_PACKED = "unknown_packed"


@dataclass
class SectionEntropy:
    """Bir binary section'in entropy bilgisi."""
    name: str
    offset: int
    size: int
    entropy: float
    is_packed: bool  # entropy > 7.0


@dataclass
class PackingInfo:
    """Packing tespit sonucu."""
    is_packed: bool
    packing_type: PackingType
    confidence: float           # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)
    section_entropies: list[SectionEntropy] = field(default_factory=list)
    overall_entropy: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict'e donustur."""
        return {
            "is_packed": self.is_packed,
            "packing_type": self.packing_type.value,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "section_entropies": [
                {
                    "name": se.name,
                    "offset": se.offset,
                    "size": se.size,
                    "entropy": round(se.entropy, 4),
                    "is_packed": se.is_packed,
                }
                for se in self.section_entropies
            ],
            "overall_entropy": round(self.overall_entropy, 4),
            "metadata": self.metadata,
        }


@dataclass
class ExtractedFile:
    """Acilan dosya bilgisi."""
    path: Path
    original_name: str
    file_type: str              # "pyc", "so", "dll", "data", "python_source"
    size: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class UnpackResult:
    """Acma sonucu."""
    success: bool
    packing_type: PackingType
    extracted_files: list[ExtractedFile] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    output_dir: Optional[Path] = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict'e donustur."""
        return {
            "success": self.success,
            "packing_type": self.packing_type.value,
            "extracted_count": len(self.extracted_files),
            "extracted_files": [
                {
                    "path": str(ef.path),
                    "original_name": ef.original_name,
                    "file_type": ef.file_type,
                    "size": ef.size,
                    "metadata": ef.metadata,
                }
                for ef in self.extracted_files
            ],
            "errors": self.errors,
            "duration_seconds": round(self.duration_seconds, 3),
            "output_dir": str(self.output_dir) if self.output_dir else None,
        }


# ---------------------------------------------------------------------------
# Entropy hesaplama
# ---------------------------------------------------------------------------

def calculate_entropy(data: bytes) -> float:
    """Shannon entropisini hesapla.

    PERF (v1.10.0 H5): Eski versiyon Python `for byte in data` ile
    byte-by-byte sayim yapiyordu -- 1 MB chunk icin ~100 ms. Yeni versiyon
    numpy varsa `np.bincount`, yoksa C-seviyesinde `collections.Counter`
    kullanir; 1 MB chunk ~1-5 ms (20-100x hizlanma).

    Args:
        data: Byte dizisi.

    Returns:
        float: 0.0 (uniform) - 8.0 (random/compressed/encrypted) arasi entropy.
    """
    length = len(data)
    if length == 0:
        return 0.0

    # Fast path: numpy
    try:
        import numpy as _np
        arr = _np.frombuffer(data, dtype=_np.uint8)
        counts = _np.bincount(arr, minlength=256)
        nonzero = counts[counts > 0].astype(_np.float64)
        probs = nonzero / length
        return float(-_np.sum(probs * _np.log2(probs)))
    except ImportError:
        pass

    # Fallback: Counter (C seviyesinde sayar, Python loop'tan cok daha hizli)
    from collections import Counter as _Counter
    counter = _Counter(data)
    entropy = 0.0
    for f in counter.values():
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def calculate_section_entropy(data: bytes, section_size: int = 65536) -> list[float]:
    """Veriyi section'lara bolup her birinin entropisini hesapla.

    Args:
        data: Binary verisi.
        section_size: Her section'in boyutu (byte).

    Returns:
        list: Her section'in entropy degeri.
    """
    entropies = []
    for i in range(0, len(data), section_size):
        chunk = data[i:i + section_size]
        if len(chunk) >= 256:  # cok kucuk chunk'lar yaniltici olur
            entropies.append(calculate_entropy(chunk))
    return entropies


# ---------------------------------------------------------------------------
# Magic bytes sabitleri
# ---------------------------------------------------------------------------

# UPX
UPX_MAGIC = b"UPX!"

# PyInstaller MEI magic (8 byte)
PYINSTALLER_MAGIC = b"MEI\014\013\012\013\016"

# PyInstaller cookie struct boyutu (Py3.9+: 88 byte, eski: 64 byte)
PYINSTALLER_COOKIE_SIZE_NEW = 88
PYINSTALLER_COOKIE_SIZE_OLD = 64

# Nuitka tanimlayici stringler
NUITKA_SIGNATURES = [
    b"__nuitka_",
    b"Nuitka-Scons",
    b"nuitka-compiled",
    b"NUITKA_PACKAGE_",
    b"nuitka_module",
]

# PERF (v1.10.0 H6): Tek pass icin alternatif regex.
# Eskiden her imza icin `sig in data` tarama -> 5 x O(N) full scan.
# Simdi re.finditer tek pass, ilk eslesmede cikilabilir (imza bulundu mu?).
import re as _re  # noqa: E402 (module-level re import)
_NUITKA_RE = _re.compile(
    b"|".join(_re.escape(sig) for sig in NUITKA_SIGNATURES),
)


# ---------------------------------------------------------------------------
# PackingDetector
# ---------------------------------------------------------------------------

class PackingDetector:
    """Binary packing tespiti.

    Entropy analizi, magic bytes ve heuristik kontrollerle
    bir binary'nin paketlenip paketlenmedigini tespit eder.
    """

    # Entropy esigi: bu degerin uzerindeki section'lar packed sayilir
    PACKED_ENTROPY_THRESHOLD = 7.0

    # Cok az import = muhtemelen packed
    MIN_IMPORT_COUNT_THRESHOLD = 10

    def __init__(self, config: Config) -> None:
        self.config = config

    def detect(self, binary_path: Path) -> PackingInfo:
        """Binary'nin packing durumunu tespit et.

        Siralama:
        1. UPX magic bytes kontrolu
        2. PyInstaller magic kontrolu
        3. Nuitka string kontrolu
        4. Entropy analizi
        5. Import sayisi heuristik

        Args:
            binary_path: Analiz edilecek binary dosyasi.

        Returns:
            PackingInfo: Tespit sonucu.
        """
        binary_path = Path(binary_path).resolve()

        if not binary_path.is_file():
            return PackingInfo(
                is_packed=False,
                packing_type=PackingType.NONE,
                confidence=0.0,
                evidence=["Dosya bulunamadi: %s" % binary_path],
            )

        # v1.10.0 Batch 5B HIGH-5: limitsiz read() 10GB OOM koruma.
        # SecurityConfig.max_binary_size_bytes asilirsa analizi reddet.
        # Cagrici binary'yi once boyutu icin stat ediyor; biz de ikinci
        # defa kontrol ediyoruz (TOCTOU safe -- fstat kullaniyoruz).
        max_size = self.config.security.max_binary_size_bytes
        try:
            with open(binary_path, "rb") as f:
                st = os.fstat(f.fileno())
                if st.st_size > max_size:
                    return PackingInfo(
                        is_packed=False,
                        packing_type=PackingType.NONE,
                        confidence=0.0,
                        evidence=[
                            "Binary cok buyuk: %d > %d byte (OOM koruma)" % (st.st_size, max_size),
                        ],
                    )
                data = f.read()
        except OSError as exc:
            return PackingInfo(
                is_packed=False,
                packing_type=PackingType.NONE,
                confidence=0.0,
                evidence=["Dosya okunamadi: %s" % exc],
            )

        evidence = []
        metadata = {}

        # 1. UPX kontrolu
        upx_result = self._check_upx(data)
        if upx_result:
            evidence.append("UPX magic bytes bulundu")
            # UPX header offset'ini kaydet
            metadata["upx_offset"] = upx_result

            # Section entropies
            section_entropies = self._analyze_section_entropies(data, binary_path.name)
            overall = calculate_entropy(data)

            return PackingInfo(
                is_packed=True,
                packing_type=PackingType.UPX,
                confidence=0.95,
                evidence=evidence,
                section_entropies=section_entropies,
                overall_entropy=overall,
                metadata=metadata,
            )

        # 2. PyInstaller kontrolu
        pyinst_result = self._check_pyinstaller(data)
        if pyinst_result:
            evidence.append("PyInstaller MEI magic bulundu")
            metadata.update(pyinst_result)

            section_entropies = self._analyze_section_entropies(data, binary_path.name)
            overall = calculate_entropy(data)

            return PackingInfo(
                is_packed=True,
                packing_type=PackingType.PYINSTALLER,
                confidence=0.95,
                evidence=evidence,
                section_entropies=section_entropies,
                overall_entropy=overall,
                metadata=metadata,
            )

        # 3. Nuitka kontrolu
        nuitka_result = self._check_nuitka(data)
        if nuitka_result:
            evidence.extend(nuitka_result)

            section_entropies = self._analyze_section_entropies(data, binary_path.name)
            overall = calculate_entropy(data)

            return PackingInfo(
                is_packed=True,
                packing_type=PackingType.NUITKA,
                confidence=0.85,
                evidence=evidence,
                section_entropies=section_entropies,
                overall_entropy=overall,
                metadata=metadata,
            )

        # 4. Entropy analizi
        overall = calculate_entropy(data)
        section_entropies = self._analyze_section_entropies(data, binary_path.name)

        packed_sections = [se for se in section_entropies if se.is_packed]
        packed_ratio = len(packed_sections) / len(section_entropies) if section_entropies else 0

        if overall > self.PACKED_ENTROPY_THRESHOLD:
            evidence.append(
                "Yuksek genel entropy: %.4f (esik: %.1f)" % (
                    overall, self.PACKED_ENTROPY_THRESHOLD,
                )
            )

        if packed_ratio > 0.5:
            evidence.append(
                "Packed section orani: %.0f%% (%d/%d)" % (
                    packed_ratio * 100,
                    len(packed_sections),
                    len(section_entropies),
                )
            )

        # 5. Import sayisi heuristik (Mach-O / ELF icin)
        import_count = self._count_imports(data)
        if import_count is not None and import_count < self.MIN_IMPORT_COUNT_THRESHOLD:
            evidence.append(
                "Cok az import: %d (esik: %d)" % (
                    import_count, self.MIN_IMPORT_COUNT_THRESHOLD,
                )
            )

        if import_count is not None:
            metadata["import_count"] = import_count

        # Karar ver
        if overall > self.PACKED_ENTROPY_THRESHOLD and packed_ratio > 0.5:
            return PackingInfo(
                is_packed=True,
                packing_type=PackingType.UNKNOWN_PACKED,
                confidence=min(0.9, 0.5 + packed_ratio * 0.4),
                evidence=evidence,
                section_entropies=section_entropies,
                overall_entropy=overall,
                metadata=metadata,
            )
        elif overall > 6.5 and (import_count is not None and import_count < self.MIN_IMPORT_COUNT_THRESHOLD):
            return PackingInfo(
                is_packed=True,
                packing_type=PackingType.GENERIC_PACKED,
                confidence=0.6,
                evidence=evidence,
                section_entropies=section_entropies,
                overall_entropy=overall,
                metadata=metadata,
            )
        else:
            return PackingInfo(
                is_packed=False,
                packing_type=PackingType.NONE,
                confidence=1.0 - (overall / 8.0),  # dusuk entropy = yuksek "not packed" confidence
                evidence=evidence if evidence else ["Packing belirtisi yok"],
                section_entropies=section_entropies,
                overall_entropy=overall,
                metadata=metadata,
            )

    @staticmethod
    def _check_upx(data: bytes) -> Optional[int]:
        """UPX magic bytes ara.

        Args:
            data: Binary verisi.

        Returns:
            int veya None: UPX magic offset'i, bulunamazsa None.
        """
        offset = data.find(UPX_MAGIC)
        if offset >= 0:
            return offset
        return None

    @staticmethod
    def _check_pyinstaller(data: bytes) -> Optional[dict[str, Any]]:
        """PyInstaller MEI magic bytes ara.

        PyInstaller binary'lerinin sonunda bir "cookie" yapisi vardir.
        Bu cookie MEI magic ile baslar ve TOC (Table of Contents) offset'ini icerir.

        Args:
            data: Binary verisi.

        Returns:
            dict veya None: PyInstaller metadata, bulunamazsa None.
        """
        # PyInstaller cookie genellikle dosyanin son 4096 byte'inda
        search_region = data[-4096:] if len(data) > 4096 else data
        offset = search_region.find(PYINSTALLER_MAGIC)

        if offset < 0:
            # Tum dosyada ara (yavas ama kesin)
            offset = data.find(PYINSTALLER_MAGIC)
            if offset < 0:
                return None
        else:
            # Gercek offset'e donustur
            offset = len(data) - len(search_region) + offset

        result = {
            "cookie_offset": offset,
            "magic_found": True,
        }

        # Cookie struct'ini parse etmeye calis
        # Format (Py3.9+, 88 byte):
        #   magic (8) + len_of_package (4) + toc_offset (4) + toc_len (4)
        #   + python_version (4) + python_dll (64)
        remaining = len(data) - offset
        if remaining >= PYINSTALLER_COOKIE_SIZE_NEW:
            try:
                cookie_data = data[offset:offset + PYINSTALLER_COOKIE_SIZE_NEW]
                # magic (8) + package_len (I) + toc_offset (I) + toc_len (I) + py_version (I)
                magic, pkg_len, toc_off, toc_len, py_ver = struct.unpack(
                    "!8sIIII", cookie_data[:24],
                )
                result["package_length"] = pkg_len
                result["toc_offset"] = toc_off
                result["toc_length"] = toc_len
                result["python_version"] = py_ver
                result["cookie_format"] = "new"
            except struct.error:
                result["cookie_format"] = "parse_error"
        elif remaining >= PYINSTALLER_COOKIE_SIZE_OLD:
            try:
                cookie_data = data[offset:offset + PYINSTALLER_COOKIE_SIZE_OLD]
                magic, pkg_len, toc_off, toc_len, py_ver = struct.unpack(
                    "!8sIIII", cookie_data[:24],
                )
                result["package_length"] = pkg_len
                result["toc_offset"] = toc_off
                result["toc_length"] = toc_len
                result["python_version"] = py_ver
                result["cookie_format"] = "old"
            except struct.error:
                result["cookie_format"] = "parse_error"

        return result

    @staticmethod
    def _check_nuitka(data: bytes) -> Optional[list[str]]:
        """Nuitka imza stringlerini ara.

        PERF (v1.10.0 H6): Tek regex pass. Eski kod her imza icin ayri
        `sig in data` tarama yapiyordu (5 x O(N)). Yeni versiyon birlesik
        alternation regex (`_NUITKA_RE`) ile tek pass. Bulunan tum benzersiz
        eslesmeler toplanir.

        Args:
            data: Binary verisi.

        Returns:
            list veya None: Bulunan Nuitka imza listesi, bulunamazsa None.
        """
        found_sigs: set[bytes] = set()
        for m in _NUITKA_RE.finditer(data):
            found_sigs.add(m.group())
            # 5 imzadan 5'i bulundu -> erken cik
            if len(found_sigs) >= len(NUITKA_SIGNATURES):
                break
        if not found_sigs:
            return None
        # Orijinal sirayi koru (NUITKA_SIGNATURES order)
        return [
            "Nuitka imzasi: %s" % sig.decode("ascii", errors="replace")
            for sig in NUITKA_SIGNATURES
            if sig in found_sigs
        ]

    def _analyze_section_entropies(self, data: bytes, name: str) -> list[SectionEntropy]:
        """Binary veriyi section'lara bolup entropy hesapla.

        Mach-O veya ELF section bilgisi parse edilemezse,
        64KB'lik bloklara bolerek genel analiz yapar.

        Args:
            data: Binary verisi.
            name: Dosya adi (loglama icin).

        Returns:
            list: SectionEntropy nesneleri.
        """
        sections = []

        # lief ile gercek section bilgisi almaya calis
        try:
            import lief
            binary = lief.parse(data)
            if binary is not None and hasattr(binary, "sections"):
                for sec in binary.sections:
                    sec_data = bytes(sec.content) if hasattr(sec, "content") else b""
                    if len(sec_data) < 256:
                        continue
                    ent = calculate_entropy(sec_data)
                    sections.append(SectionEntropy(
                        name=sec.name or "(unnamed)",
                        offset=sec.offset if hasattr(sec, "offset") else 0,
                        size=len(sec_data),
                        entropy=ent,
                        is_packed=ent > self.PACKED_ENTROPY_THRESHOLD,
                    ))
                if sections:
                    return sections
        except Exception:
            logger.debug("lief yoksa veya parse basarisiz olursa fallback", exc_info=True)

        # Fallback: 64KB bloklara bol
        block_size = 65536
        for i in range(0, len(data), block_size):
            chunk = data[i:i + block_size]
            if len(chunk) < 256:
                continue
            ent = calculate_entropy(chunk)
            sections.append(SectionEntropy(
                name="block_%04d" % (i // block_size),
                offset=i,
                size=len(chunk),
                entropy=ent,
                is_packed=ent > self.PACKED_ENTROPY_THRESHOLD,
            ))

        return sections

    @staticmethod
    def _count_imports(data: bytes) -> Optional[int]:
        """Binary'deki import sayisini tahmin et.

        lief ile gercek import tablosunu okumaya calisir.
        Basarisiz olursa None dondurur.

        Args:
            data: Binary verisi.

        Returns:
            int veya None: Import sayisi.
        """
        try:
            import lief
            binary = lief.parse(data)
            if binary is None:
                return None

            # Mach-O: imported symbols
            if hasattr(binary, "imported_symbols"):
                symbols = list(binary.imported_symbols)
                return len(symbols)

            # ELF: imported functions
            if hasattr(binary, "imported_functions"):
                return len(list(binary.imported_functions))

        except Exception:
            logger.debug("Unpack islemi basarisiz, atlaniyor", exc_info=True)

        return None


# ---------------------------------------------------------------------------
# PyInstallerExtractor
# ---------------------------------------------------------------------------

class PyInstallerExtractor:
    """PyInstaller archive parser ve extractor.

    PyInstaller binary'lerinden:
    - TOC (Table of Contents) parse
    - .pyc dosyalarini cikar
    - marshal/dis ile bytecode analiz (opsiyonel)
    - uncompyle6/decompyle3 ile kaynak koda donustur (opsiyonel)
    """

    # PyInstaller TOC entry tipleri
    TOC_TYPES = {
        ord("s"): "SCRIPT",        # Python script
        ord("M"): "MODULE",        # Python module
        ord("m"): "MODULE_PACKAGE", # Python package module
        ord("b"): "BINARY",        # Binary extension (.so/.dll)
        ord("z"): "ZIPFILE",       # Zip file
        ord("d"): "DATA",          # Data file
        ord("o"): "OPTION",        # Runtime option
    }

    def __init__(self, config: Config) -> None:
        self.config = config

    def extract(self, binary_path: Path, output_dir: Path) -> UnpackResult:
        """PyInstaller binary'den dosyalari cikar.

        Args:
            binary_path: PyInstaller binary dosyasi.
            output_dir: Cikarilan dosyalarin yazilacagi dizin.

        Returns:
            UnpackResult: Cikartma sonucu.
        """
        start = time.monotonic()
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        errors = []
        extracted = []

        try:
            with open(binary_path, "rb") as f:
                data = f.read()
        except OSError as exc:
            return UnpackResult(
                success=False,
                packing_type=PackingType.PYINSTALLER,
                errors=["Dosya okunamadi: %s" % exc],
                duration_seconds=time.monotonic() - start,
                output_dir=output_dir,
            )

        # Cookie'yi bul
        cookie_offset = data.find(PYINSTALLER_MAGIC)
        if cookie_offset < 0:
            return UnpackResult(
                success=False,
                packing_type=PackingType.PYINSTALLER,
                errors=["PyInstaller cookie bulunamadi"],
                duration_seconds=time.monotonic() - start,
                output_dir=output_dir,
            )

        # Cookie'den TOC bilgisini oku
        try:
            toc_info = self._parse_cookie(data, cookie_offset)
        except Exception as exc:
            return UnpackResult(
                success=False,
                packing_type=PackingType.PYINSTALLER,
                errors=["Cookie parse hatasi: %s" % exc],
                duration_seconds=time.monotonic() - start,
                output_dir=output_dir,
            )

        # Package offset hesapla
        pkg_start = cookie_offset - toc_info["package_length"]
        if pkg_start < 0:
            pkg_start = 0

        # TOC'u parse et
        toc_entries = self._parse_toc(
            data,
            pkg_start + toc_info["toc_offset"],
            toc_info["toc_length"],
        )

        logger.info(
            "PyInstaller TOC: %d entry, package @ %d, toc @ %d",
            len(toc_entries), pkg_start, toc_info["toc_offset"],
        )

        # Her entry'yi cikar
        for entry in toc_entries:
            try:
                extracted_file = self._extract_entry(
                    data, pkg_start, entry, output_dir,
                )
                if extracted_file is not None:
                    extracted.append(extracted_file)
            except Exception as exc:
                errors.append("Entry cikartma hatasi (%s): %s" % (entry.get("name", "?"), exc))

        # .pyc dosyalarini decompile etmeye calis
        pyc_files = [ef for ef in extracted if ef.file_type == "pyc"]
        if pyc_files:
            decompiled = self._try_decompile_pyc_files(pyc_files, output_dir)
            extracted.extend(decompiled)

        duration = time.monotonic() - start

        return UnpackResult(
            success=len(extracted) > 0,
            packing_type=PackingType.PYINSTALLER,
            extracted_files=extracted,
            errors=errors,
            duration_seconds=duration,
            output_dir=output_dir,
        )

    @staticmethod
    def _parse_cookie(data: bytes, offset: int) -> dict[str, Any]:
        """PyInstaller cookie struct'ini parse et.

        Args:
            data: Binary verisi.
            offset: Cookie baslangic offset'i.

        Returns:
            dict: Cookie bilgileri.
        """
        # 8s: magic, I: pkg_len, I: toc_off, I: toc_len, I: py_ver
        cookie = struct.unpack("!8sIIII", data[offset:offset + 24])
        return {
            "magic": cookie[0],
            "package_length": cookie[1],
            "toc_offset": cookie[2],
            "toc_length": cookie[3],
            "python_version": cookie[4],
        }

    @staticmethod
    def _parse_toc(data: bytes, toc_start: int, toc_length: int) -> list[dict[str, Any]]:
        """TOC (Table of Contents) parse et.

        Her TOC entry formati:
            entry_length (I) + entry_offset (I) + data_length (I) +
            uncompress_length (I) + compress_flag (B) + type_flag (B) +
            name (null-terminated string)

        Args:
            data: Binary verisi.
            toc_start: TOC baslangic offset'i.
            toc_length: TOC uzunlugu (byte).

        Returns:
            list: TOC entry listesi.
        """
        entries = []
        pos = toc_start
        end = toc_start + toc_length

        while pos < end and pos < len(data):
            # En az 18 byte header gerekli
            if pos + 18 > len(data):
                break

            try:
                entry_len, entry_off, data_len, uncomp_len, cflag, tflag = struct.unpack(
                    "!IIIBB", data[pos + 4:pos + 18],  # ilk 4 byte entry_len'in kendisi
                )
                # entry_len includes itself
                raw_entry_len = struct.unpack("!I", data[pos:pos + 4])[0]

                # Name: 18. byte'tan entry sonuna kadar, null-terminated
                name_start = pos + 18
                name_end = pos + raw_entry_len
                if name_end > len(data):
                    name_end = len(data)

                name_bytes = data[name_start:name_end]
                # Null terminator'u kes
                null_idx = name_bytes.find(b"\x00")
                if null_idx >= 0:
                    name_bytes = name_bytes[:null_idx]

                name = name_bytes.decode("utf-8", errors="replace")

                type_name = PyInstallerExtractor.TOC_TYPES.get(tflag, "UNKNOWN_%d" % tflag)

                entries.append({
                    "name": name,
                    "entry_offset": entry_off,
                    "data_length": data_len,
                    "uncompressed_length": uncomp_len,
                    "is_compressed": cflag == 1,
                    "type_flag": tflag,
                    "type_name": type_name,
                })

                pos += raw_entry_len
                if raw_entry_len == 0:
                    break  # sonsuz dongu korumasi

            except struct.error:
                break

        return entries

    @staticmethod
    def _extract_entry(
        data: bytes,
        pkg_start: int,
        entry: dict[str, Any],
        output_dir: Path,
    ) -> Optional[ExtractedFile]:
        """Tek bir TOC entry'sini dosyaya cikar.

        Args:
            data: Binary verisi.
            pkg_start: Package baslangic offset'i.
            entry: TOC entry bilgileri.
            output_dir: Cikti dizini.

        Returns:
            ExtractedFile veya None.
        """
        name = entry["name"]
        if not name:
            return None

        # v1.10.0 Batch 5B MED-11: Windows reserved names reddet.
        # APK/PyInstaller icinde "CON.txt" -> Windows host'ta device acar.
        if _is_windows_reserved(name):
            logger.warning("PyInstaller entry Windows reserved name, reddedildi: %s", name)
            return None

        offset = pkg_start + entry["entry_offset"]
        length = entry["data_length"]

        # v1.10.0 Batch 5B MED-17: TOC entry sanity checks.
        if offset < 0 or length < 0 or length > len(data) or offset + length > len(data):
            logger.warning(
                "PyInstaller entry offset/length sanity check fail: "
                "offset=%d length=%d total=%d",
                offset, length, len(data),
            )
            return None

        raw = data[offset:offset + length]

        # v1.10.0 Batch 5B CRITICAL-3: streaming zlib decompress + bomb koruma.
        # Eski `zlib.decompress(raw)` tek seferde acardi; 1KB input 10GB
        # uncompressed olabilir. Yeni ``safe_zlib_decompress`` max_size+1
        # isteyip erken bomb tespiti yapar.
        if entry["is_compressed"] and length > 0:
            decompressed = safe_zlib_decompress(
                raw, max_size=_MAX_PYINSTALLER_DECOMPRESS,
            )
            if decompressed is None:
                logger.warning(
                    "PyInstaller entry decompress reddedildi (bomb/hatali): %s",
                    name,
                )
                return None
            # Uncompressed_length ile tutarlilik (metadata guvenilmez ama sinyal)
            expected = entry.get("uncompressed_length", 0)
            if expected and abs(len(decompressed) - expected) > (expected // 10 + 1024):
                logger.debug(
                    "PyInstaller uncompressed_length uyusmazlik: "
                    "meta=%d actual=%d (%s)",
                    expected, len(decompressed), name,
                )
            raw = decompressed

        # Dosya adini guvenli hale getir
        safe_name = name.replace("/", os.sep).replace("\\", os.sep)
        safe_name = safe_name.lstrip(os.sep).lstrip(".")
        # .. dizileri kaldir (path traversal)
        parts = [p for p in safe_name.split(os.sep) if p not in ("..", ".")]
        safe_name = os.sep.join(parts) if parts else "unnamed"

        out_path = (output_dir / safe_name).resolve()
        # v1.10.0 Fix Sprint HIGH-1: Path.relative_to ile prefix confusion
        # kapatildi. "/tmp/stage" vs "/tmp/stage-evil/..." guvenle ayrilir.
        try:
            out_path.relative_to(output_dir.resolve())
        except ValueError:
            logger.warning("Path traversal engellendi: %s", name)
            return None

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(raw)

        # Dosya tipini belirle
        file_type = "data"
        type_name = entry.get("type_name", "")
        if type_name in ("SCRIPT", "MODULE", "MODULE_PACKAGE"):
            file_type = "pyc"
        elif type_name == "BINARY":
            file_type = "binary_extension"
        elif type_name == "ZIPFILE":
            file_type = "zip"

        return ExtractedFile(
            path=out_path,
            original_name=name,
            file_type=file_type,
            size=len(raw),
            metadata={
                "type_name": type_name,
                "was_compressed": entry["is_compressed"],
                "original_length": entry["data_length"],
                "uncompressed_length": entry["uncompressed_length"],
            },
        )

    @staticmethod
    def _try_decompile_pyc_files(
        pyc_files: list[ExtractedFile],
        output_dir: Path,
    ) -> list[ExtractedFile]:
        """pyc dosyalarini Python kaynak koduna donusturmeye calis.

        uncompyle6 veya decompyle3 kurulu ise calistirir.

        Args:
            pyc_files: .pyc ExtractedFile listesi.
            output_dir: Cikti dizini.

        Returns:
            list: Decompile edilmis ExtractedFile listesi.
        """
        decompiled = []

        # v1.10.0 Batch 5B CRITICAL-2: resolve_tool ile PATH hijack koruma.
        decompiler = None
        decompiler_path = None
        for tool in ["uncompyle6", "decompyle3"]:
            resolved = resolve_tool(tool)
            if resolved is not None:
                decompiler = tool
                decompiler_path = resolved
                break

        if decompiler is None:
            logger.debug("pyc decompiler (uncompyle6/decompyle3) bulunamadi, atlaniyor")
            return decompiled

        decompiled_dir = output_dir / "decompiled_python"
        decompiled_dir.mkdir(parents=True, exist_ok=True)

        for pyc_file in pyc_files:
            out_name = pyc_file.original_name
            if out_name.endswith(".pyc"):
                out_name = out_name[:-4]
            out_name = out_name.replace("/", "_").replace("\\", "_")
            out_path = decompiled_dir / (out_name + ".py")

            try:
                # decompiler_path: resolve_tool ile onceden dogrulanmis
                result = safe_run(
                    [decompiler_path or decompiler, "-o", str(out_path), str(pyc_file.path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0 and out_path.exists():
                    decompiled.append(ExtractedFile(
                        path=out_path,
                        original_name=pyc_file.original_name,
                        file_type="python_source",
                        size=out_path.stat().st_size,
                        metadata={"decompiler": decompiler, "source_pyc": str(pyc_file.path)},
                    ))
                else:
                    logger.debug(
                        "Decompile basarisiz: %s: %s",
                        pyc_file.original_name,
                        result.stderr[:200],
                    )
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.debug(
                    "Decompile hatasi: %s: %s", pyc_file.original_name, exc,
                )

        return decompiled


# ---------------------------------------------------------------------------
# BinaryUnpacker
# ---------------------------------------------------------------------------

class BinaryUnpacker:
    """Packed binary acici.

    PackingDetector sonucuna gore uygun acma yontemini secip uygular.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self._pyinstaller_extractor = PyInstallerExtractor(config)

    def unpack(
        self,
        binary_path: Path,
        packing: PackingInfo,
        output_dir: Path,
    ) -> UnpackResult:
        """Packed binary'yi ac.

        Args:
            binary_path: Packed binary dosyasi.
            packing: PackingDetector sonucu.
            output_dir: Cikarilan dosyalarin yazilacagi dizin.

        Returns:
            UnpackResult: Acma sonucu.
        """
        binary_path = Path(binary_path).resolve()
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if not packing.is_packed:
            return UnpackResult(
                success=False,
                packing_type=PackingType.NONE,
                errors=["Binary packed degil, acma gereksiz"],
                output_dir=output_dir,
            )

        ptype = packing.packing_type

        if ptype == PackingType.UPX:
            return self._unpack_upx(binary_path, output_dir)
        elif ptype == PackingType.PYINSTALLER:
            return self._pyinstaller_extractor.extract(binary_path, output_dir)
        elif ptype == PackingType.NUITKA:
            return self._extract_nuitka_metadata(binary_path, output_dir)
        else:
            return self._unpack_generic(binary_path, packing, output_dir)

    def _unpack_upx(self, binary_path: Path, output_dir: Path) -> UnpackResult:
        """UPX ile paketlenmis binary'yi ac.

        ``upx -d`` komutu ile decompress eder. UPX kurulu degilse
        hata dondurur.

        Args:
            binary_path: UPX packed binary.
            output_dir: Cikti dizini.

        Returns:
            UnpackResult: Acma sonucu.
        """
        start = time.monotonic()
        errors = []

        # v1.10.0 Batch 5B CRITICAL-2: resolve_tool ile PATH hijack koruma.
        upx_path = resolve_tool("upx")
        if upx_path is None:
            return UnpackResult(
                success=False,
                packing_type=PackingType.UPX,
                errors=["UPX bulunamadi. Kurmak icin: brew install upx"],
                duration_seconds=time.monotonic() - start,
                output_dir=output_dir,
            )

        # Binary'nin kopyasini olustur (UPX in-place degistirir)
        unpacked_path = output_dir / binary_path.name
        try:
            shutil.copy2(str(binary_path), str(unpacked_path))
        except OSError as exc:
            return UnpackResult(
                success=False,
                packing_type=PackingType.UPX,
                errors=["Dosya kopyalanamadi: %s" % exc],
                duration_seconds=time.monotonic() - start,
                output_dir=output_dir,
            )

        # upx -d ile decompress (safe_run: LD_PRELOAD-drop + whitelist env)
        try:
            result = safe_run(
                [upx_path, "-d", str(unpacked_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                extracted = [ExtractedFile(
                    path=unpacked_path,
                    original_name=binary_path.name,
                    file_type="unpacked_binary",
                    size=unpacked_path.stat().st_size,
                    metadata={
                        "original_size": binary_path.stat().st_size,
                        "unpacked_size": unpacked_path.stat().st_size,
                        "upx_output": result.stdout[:500],
                    },
                )]

                return UnpackResult(
                    success=True,
                    packing_type=PackingType.UPX,
                    extracted_files=extracted,
                    duration_seconds=time.monotonic() - start,
                    output_dir=output_dir,
                )
            else:
                errors.append("UPX decompress basarisiz: %s" % result.stderr[:500])
                # Kopyayi sil
                try:
                    unpacked_path.unlink()
                except OSError:
                    pass

        except subprocess.TimeoutExpired:
            errors.append("UPX zaman asimi (120s)")
        except OSError as exc:
            errors.append("UPX calistirma hatasi: %s" % exc)

        return UnpackResult(
            success=False,
            packing_type=PackingType.UPX,
            errors=errors,
            duration_seconds=time.monotonic() - start,
            output_dir=output_dir,
        )

    @staticmethod
    def _extract_nuitka_metadata(
        binary_path: Path, output_dir: Path,
    ) -> UnpackResult:
        """Nuitka binary'den metadata cikar.

        Nuitka binary'leri gercek anlamda "unpack" edilemez cunku
        C koduna derlenmistir. Bunun yerine metadata ve goemulu
        string'ler cikarilir.

        Args:
            binary_path: Nuitka binary.
            output_dir: Cikti dizini.

        Returns:
            UnpackResult: Metadata cikartma sonucu.
        """
        start = time.monotonic()
        errors = []
        extracted = []

        try:
            with open(binary_path, "rb") as f:
                data = f.read()
        except OSError as exc:
            return UnpackResult(
                success=False,
                packing_type=PackingType.NUITKA,
                errors=["Dosya okunamadi: %s" % exc],
                duration_seconds=time.monotonic() - start,
                output_dir=output_dir,
            )

        # Nuitka metadatasini cikar
        metadata = {
            "nuitka_signatures_found": [],
            "python_strings": [],
            "module_names": [],
        }

        for sig in NUITKA_SIGNATURES:
            if sig in data:
                metadata["nuitka_signatures_found"].append(
                    sig.decode("ascii", errors="replace")
                )

        # "__nuitka_" ile baslayan tum stringleri bul
        import re
        nuitka_strings = re.findall(
            b"__nuitka_[a-zA-Z0-9_]+",
            data,
        )
        metadata["python_strings"] = [
            s.decode("ascii", errors="replace") for s in set(nuitka_strings)
        ]

        # Python module isimleri (genellikle null-terminated ASCII string olarak gomulur)
        # ".py" ile biten stringleri ara
        py_modules = re.findall(
            b"[a-zA-Z_][a-zA-Z0-9_./]{2,60}\\.py[co]?",
            data,
        )
        metadata["module_names"] = sorted(set(
            m.decode("ascii", errors="replace") for m in py_modules
        ))[:200]  # max 200

        # Metadata'yi dosyaya kaydet
        import json
        meta_path = output_dir / "nuitka_metadata.json"
        meta_path.write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        extracted.append(ExtractedFile(
            path=meta_path,
            original_name="nuitka_metadata.json",
            file_type="data",
            size=meta_path.stat().st_size,
            metadata={"type": "nuitka_metadata"},
        ))

        return UnpackResult(
            success=True,
            packing_type=PackingType.NUITKA,
            extracted_files=extracted,
            duration_seconds=time.monotonic() - start,
            output_dir=output_dir,
        )

    def _unpack_generic(
        self,
        binary_path: Path,
        packing: PackingInfo,
        output_dir: Path,
    ) -> UnpackResult:
        """Bilinmeyen packer icin entropy-based section extraction.

        Yuksek entropyili section'lari ayri dosyalara cikarir ve
        dusuk entropyili section'lari (muhtemelen orijinal kod)
        analiz icin kaydeder.

        Args:
            binary_path: Packed binary.
            packing: PackingInfo sonucu.
            output_dir: Cikti dizini.

        Returns:
            UnpackResult: Extraction sonucu.
        """
        start = time.monotonic()
        errors = []
        extracted = []

        try:
            with open(binary_path, "rb") as f:
                data = f.read()
        except OSError as exc:
            return UnpackResult(
                success=False,
                packing_type=packing.packing_type,
                errors=["Dosya okunamadi: %s" % exc],
                duration_seconds=time.monotonic() - start,
                output_dir=output_dir,
            )

        # lief ile section extraction dene
        section_extracted = False
        try:
            import lief
            binary = lief.parse(data)
            if binary is not None and hasattr(binary, "sections"):
                for sec in binary.sections:
                    sec_data = bytes(sec.content) if hasattr(sec, "content") else b""
                    if len(sec_data) < 256:
                        continue

                    entropy = calculate_entropy(sec_data)
                    sec_name = sec.name or "unnamed"
                    safe_name = sec_name.strip(".").replace("/", "_").replace("\\", "_")
                    if not safe_name:
                        safe_name = "section_%d" % sec.offset if hasattr(sec, "offset") else "section"

                    out_path = output_dir / ("%s.bin" % safe_name)
                    out_path.write_bytes(sec_data)

                    extracted.append(ExtractedFile(
                        path=out_path,
                        original_name=sec_name,
                        file_type="section",
                        size=len(sec_data),
                        metadata={
                            "entropy": round(entropy, 4),
                            "is_packed": entropy > PackingDetector.PACKED_ENTROPY_THRESHOLD,
                            "offset": sec.offset if hasattr(sec, "offset") else 0,
                        },
                    ))
                    section_extracted = True
        except Exception as exc:
            errors.append("lief section extraction hatasi: %s" % exc)

        if not section_extracted:
            # Fallback: 64KB bloklara bol
            block_size = 65536
            for i in range(0, len(data), block_size):
                chunk = data[i:i + block_size]
                if len(chunk) < 256:
                    continue
                entropy = calculate_entropy(chunk)

                out_path = output_dir / ("block_%06x.bin" % i)
                out_path.write_bytes(chunk)

                extracted.append(ExtractedFile(
                    path=out_path,
                    original_name="offset_0x%06x" % i,
                    file_type="section",
                    size=len(chunk),
                    metadata={
                        "entropy": round(entropy, 4),
                        "is_packed": entropy > PackingDetector.PACKED_ENTROPY_THRESHOLD,
                        "offset": i,
                    },
                ))

        return UnpackResult(
            success=len(extracted) > 0,
            packing_type=packing.packing_type,
            extracted_files=extracted,
            errors=errors,
            duration_seconds=time.monotonic() - start,
            output_dir=output_dir,
        )


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------

def analyze_packed_binary(
    binary_path: Path,
    output_dir: Optional[Path] = None,
    config: Optional[Config] = None,
) -> dict[str, Any]:
    """Packed binary tespiti ve acma islemini tek cagrida yap.

    Kullanim:
        result = analyze_packed_binary(Path("/path/to/binary"))
        if result["packing"]["is_packed"]:
            print("Packed: %s" % result["packing"]["packing_type"])
            print("Extracted: %d files" % result["unpack"]["extracted_count"])

    Args:
        binary_path: Analiz edilecek binary.
        output_dir: Cikarilan dosyalar icin dizin (None ise temp dizin).
        config: Konfigurasyon (None ise varsayilan).

    Returns:
        dict: {"packing": PackingInfo.to_dict(), "unpack": UnpackResult.to_dict() | None}
    """
    if config is None:
        config = Config()

    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="karadul_unpack_"))

    detector = PackingDetector(config)
    packing = detector.detect(binary_path)

    result = {
        "binary": str(binary_path),
        "packing": packing.to_dict(),
        "unpack": None,
    }

    if packing.is_packed:
        unpacker = BinaryUnpacker(config)
        unpack_result = unpacker.unpack(binary_path, packing, output_dir)
        result["unpack"] = unpack_result.to_dict()

    return result
