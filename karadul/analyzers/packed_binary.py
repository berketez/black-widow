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
import unicodedata
import zlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from karadul.analyzers.pyc_decompiler import repair_pyc_header, version_from_pyc_bytes
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

# Cookie'nin sabit başı (PyInstaller archive/writers.py, CArchive cookie): magic(8) +
# paket uzunluğu + TOC ofseti + TOC uzunluğu + Python sürümü, hepsi BIG-endian.
# Cookie okuma TEK KAYNAK: PackingDetector, PyInstallerExtractor ve python_binary'nin
# static TOC'si buradan okur (static kopya little-endian okuyup gerçek binary'lerde
# python_version="9395896.32" ve 0 TOC girdisi üretiyordu).
_PYINSTALLER_COOKIE_HEAD = struct.Struct("!8sIIII")


def parse_pyinstaller_cookie(data: bytes, offset: int) -> dict[str, Any]:
    """``offset``'teki PyInstaller cookie başını oku. Veri kısaysa ``struct.error``."""
    magic, pkg_len, toc_off, toc_len, pyver = _PYINSTALLER_COOKIE_HEAD.unpack_from(data, offset)
    return {
        "magic": magic,
        "package_length": pkg_len,
        "toc_offset": toc_off,
        "toc_length": toc_len,
        "python_version": pyver,
    }


def pyinstaller_python_version(pyver: int) -> Optional[str]:
    """Cookie'deki sürüm tamsayısı -> ``"3.12"``; makul değilse None.

    PyInstaller >= 3 ``major * 100 + minor`` yazar (312); eski sürümler
    ``major * 10 + minor`` (27). Yanlış okunmuş/bozuk değer sürüm diye raporlanmaz.
    """
    if pyver <= 0:
        return None
    major, minor = divmod(pyver, 100) if pyver >= 100 else divmod(pyver, 10)
    if major not in (2, 3):
        return None
    return "%d.%d" % (major, minor)


def locate_pyinstaller_archive(data: bytes) -> Optional[dict[str, Any]]:
    """Gerçek cookie'yi bul; paket başlangıcını ve TOC konumunu hesapla.

    Cookie paketin SONUNDADIR; bootloader MEI magic'ini başka yerde de
    referanslayabilir, bu yüzden son eşleşme (``rfind``) alınır. Cookie, paket
    içinde TOC'nin hemen ardındadır: ``pkg_start = cookie - toc_offset - toc_length``.
    Bu hesap cookie boyutundan bağımsızdır (24/88 bayt) ve macOS imzalı onefile'da
    da doğrudur (sondaki imza ofseti kaydırmaz).

    Returns:
        None (magic yok) ya da ``parse_pyinstaller_cookie`` alanları + ``cookie_offset``,
        ``pkg_start``, ``toc_start``. Cookie kısa ise ``struct.error`` yükselir.
    """
    cookie_offset = data.rfind(PYINSTALLER_MAGIC)
    if cookie_offset < 0:
        return None
    info = parse_pyinstaller_cookie(data, cookie_offset)
    pkg_start = max(0, cookie_offset - info["toc_offset"] - info["toc_length"])
    info["cookie_offset"] = cookie_offset
    info["pkg_start"] = pkg_start
    info["toc_start"] = pkg_start + info["toc_offset"]
    return info


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
        """UPX paketleyici imzasi ara.

        v1.14.5 GUVENLIK FIX: Eski versiyon sadece 4-byte ``b"UPX!"`` sentinel'i
        ariyordu; bu rastgele/kullanici verisinde false positive uretiyordu
        (orn. herhangi bir binary'de "UPX!" alt-stringi). Gercek UPX paketli
        bir dosyada PE/ELF section header'larinda ``UPX0`` ve ``UPX1`` adli
        section'lar bulunur. Her uc isaretin de varligini sart kosarak false
        positive orani ciddi sekilde dusurulur (security-expert review,
        v1.14.5 P5).

        Args:
            data: Binary verisi.

        Returns:
            int veya None: UPX magic (``UPX!``) offset'i. UPX0 veya UPX1
            isaretlerinden biri eksikse ``None`` (false positive guard).
        """
        offset = data.find(UPX_MAGIC)
        if offset < 0:
            return None
        # Section name'lerin ikisi de bulunmali (gercek UPX layout'u).
        if data.find(b"UPX0") < 0 or data.find(b"UPX1") < 0:
            return None
        return offset

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

        result: dict[str, Any] = {
            "cookie_offset": offset,
            "magic_found": True,
        }

        # Cookie başı (tek kaynak: parse_pyinstaller_cookie). Yeni biçim 88 bayt
        # (+ python_dll 64), eski 64 bayt; ilk 24 bayt ikisinde de aynı.
        remaining = len(data) - offset
        if remaining >= PYINSTALLER_COOKIE_SIZE_OLD:
            try:
                cookie = parse_pyinstaller_cookie(data, offset)
            except struct.error:
                result["cookie_format"] = "parse_error"
            else:
                for key in ("package_length", "toc_offset", "toc_length", "python_version"):
                    result[key] = cookie[key]
                result["cookie_format"] = (
                    "new" if remaining >= PYINSTALLER_COOKIE_SIZE_NEW else "old"
                )

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
                    # lief section.name `str | bytes` — bytes ise decode et.
                    raw_name = sec.name
                    if isinstance(raw_name, bytes):
                        sec_name = raw_name.decode("utf-8", errors="replace") or "(unnamed)"
                    else:
                        sec_name = raw_name or "(unnamed)"
                    sections.append(SectionEntropy(
                        name=sec_name,
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

        Native crash koruma: lief.parse() subprocess izolasyonunda
        calistirilir (v1.12 teknik borc). Malformed/packed binary
        cocuk process'i SIGSEGV'le oldurse bile None doneriz.

        Args:
            data: Binary verisi.

        Returns:
            int veya None: Import sayisi.
        """
        try:
            from karadul.utils.lief_subprocess import parse_bytes_in_subprocess
            result = parse_bytes_in_subprocess(data, timeout=30)
            if result is None:
                return None
            imports = result.get("imports") or []
            return len(imports) if imports else None
        except ImportError:
            return None
        except Exception:
            logger.debug("Lief subprocess import sayim basarisiz, atlaniyor", exc_info=True)
            return None


# ---------------------------------------------------------------------------
# PyInstaller PYZ (ZlibArchive) okuyucu
# ---------------------------------------------------------------------------
#
# Biçim PyInstaller kaynağından doğrulandı (2026-09-25): 6.15.0
# archive/writers.py (ZlibArchiveWriter) + loader/pyimod01_archive.py
# (ZlibArchiveReader); 5.13.2 ve 4.10 wheel'leri; 3.6 sdist.
#
#   [0:4]   b"PYZ\0"
#   [4:8]   Python bytecode magic (paketi derleyen yorumlayıcının MAGIC_NUMBER'ı)
#   [8:12]  TOC ofseti, struct "!i" (big-endian, işaretli), PYZ başına göre
#   [12]    3.6-5.13: şifreleme bayrağı, struct "!B" (cipher is not None).
#           6.x bu baytı yazmaz; yazıcı 17 baytı sıfırla ayırdığı için 0 kalır.
#   girdi:  zlib.compress(marshal.dumps(code), 6). Şifreliyse IV(16) + AES
#           (3.x PyCrypto CFB, 4.x-5.x tinyaes CTR). Şifreleme 6.0'da kaldırıldı.
#   TOC:    marshal.dumps([(ad, (typecode, ofset, uzunluk)), ...]). Okuyucular
#           dict(...) ile açar; burada liste de dict de kabul edilir.
#
# Güvenlik: TOC ``marshal.loads`` ile AÇILMAZ (CPython belgesi: güvenilmeyen
# veride marshal kullanılmaz; TOC'ye konan bir code nesnesi süreç içinde
# yaratılırdı). Yalnız TOC'nin kullandığı tipleri okuyan kısıtlı ayrıştırıcı
# kullanılır. Girdi gövdeleri (code nesneleri) hiç unmarshal edilmez: yalnız
# ilk baytın TYPE_CODE olduğuna bakılır, gövde .pyc olarak diske yazılır ve
# pycdc/pycdas alt süreçte ayrıştırır. Kod hiçbir aşamada çalıştırılmaz.

PYZ_MAGIC = b"PYZ\x00"
_PYZ_HEADER_SIZE = 12          # magic(4) + python magic(4) + TOC ofseti(4)
_PYZ_CRYPT_FLAG_OFFSET = 12    # 3.6-5.13 şifreleme bayrağı
# 4.x-5.x: şifreleme anahtarı bu bootstrap modülüyle CArchive'e konur
# (building/api.py PYZ.__init__, "Bundle the crypto key").
_PYI_CRYPTO_KEY_MODULE = "pyimod00_crypto_key"

# TOC typecode'ları (PyInstaller loader/pyimod01_archive.py)
PYZ_ITEM_MODULE = 0
PYZ_ITEM_PKG = 1
PYZ_ITEM_DATA = 2              # <= 5.x; pkg_resources verisi, code değil
PYZ_ITEM_NSPKG = 3             # PEP 420 namespace paketi
_PYZ_CODE_TYPECODES = frozenset({PYZ_ITEM_MODULE, PYZ_ITEM_PKG, PYZ_ITEM_NSPKG})

# Kısıtlı marshal ayrıştırıcı sınırları. Meşru TOC: liste > (ad, (tip, ofset,
# uzunluk)) > int = 4 seviye; iç demetler 2 ve 3 öğeli; ofsetler 32 bit.
_MARSHAL_FLAG_REF = 0x80
_MARSHAL_TYPE_CODE = ord("c")
_PYZ_TOC_MAX_DEPTH = 8
_PYZ_TOC_MAX_INNER_ITEMS = 8
_PYZ_TOC_MAX_LONG_DIGITS = 5   # 15 bitlik basamak -> 75 bit

# zlib gövdesi bu dilimlerle beslenir; bozuk akışta hataya kadar üretilen
# çıktı bütçeye yazılabilir. En kötü oran ~1032:1 -> sayılmayan iş <= ~16 MiB/girdi.
_PYZ_INFLATE_CHUNK = 16 * 1024

# Modül adı -> tek dosya adı. NAME_MAX 255 bayt; aşağı akışta eklenen en uzun
# ek ".partial.py"/".disasm.txt" (11) + çakışma eki "~N". Pay bırakılmış sınır.
_PYZ_MAX_NAME_BYTES = 200

# PyInstaller'ın kendi modülleri (bootstrap/loader/runtime hook yardımcıları).
_PYINSTALLER_MODULE_PREFIXES = ("pyimod", "pyiboot", "pyi_", "_pyi_")

# sys.stdlib_module_names yalnız ÇALIŞAN yorumlayıcının listesidir; .pyc başka
# sürümden olabilir. Sürümler arası farklar aşağıda (ilk var olduğu / ilk
# olmadığı sürüm). Kaynak, 2026-09-25 ölçümü: 3.10.16, 3.11.16, 3.12.7, 3.14.7
# yorumlayıcılarının sys.stdlib_module_names'i; 3.13 için CPython v3.13.7
# Python/stdlib_module_names.h; 3.10'da kalkanlar yerel 3.9.6 stdlib dizini ile
# 3.10 listesinin farkı. Tabloda olmayan ad için çalışan yorumlayıcının listesi
# kullanılır.
_STDLIB_ADDED_IN: dict[str, tuple[int, int]] = {
    "_tokenize": (3, 11), "_typing": (3, 11), "tomllib": (3, 11),
    "_pydatetime": (3, 12), "_pylong": (3, 12), "_sha2": (3, 12), "_wmi": (3, 12),
    "_android_support": (3, 13), "_apple_support": (3, 13), "_colorize": (3, 13),
    "_interpchannels": (3, 13), "_interpqueues": (3, 13), "_interpreters": (3, 13),
    "_ios_support": (3, 13), "_opcode_metadata": (3, 13), "_pyrepl": (3, 13),
    "_suggestions": (3, 13), "_sysconfig": (3, 13),
    "_ast_unparse": (3, 14), "_hmac": (3, 14), "_py_warnings": (3, 14),
    "_remote_debugging": (3, 14), "_types": (3, 14), "_zstd": (3, 14),
    "annotationlib": (3, 14), "compression": (3, 14),
}
_STDLIB_REMOVED_IN: dict[str, tuple[int, int]] = {
    "_bootlocale": (3, 10), "_peg_parser": (3, 10), "formatter": (3, 10),
    "parser": (3, 10), "symbol": (3, 10),
    "binhex": (3, 11),
    "_bootsubprocess": (3, 12), "_sha256": (3, 12), "_sha512": (3, 12),
    "asynchat": (3, 12), "asyncore": (3, 12), "distutils": (3, 12),
    "imp": (3, 12), "smtpd": (3, 12),
    "_crypt": (3, 13), "_msi": (3, 13), "aifc": (3, 13), "audioop": (3, 13),
    "cgi": (3, 13), "cgitb": (3, 13), "chunk": (3, 13), "crypt": (3, 13),
    "imghdr": (3, 13), "lib2to3": (3, 13), "mailcap": (3, 13), "msilib": (3, 13),
    "nis": (3, 13), "nntplib": (3, 13), "ossaudiodev": (3, 13), "pipes": (3, 13),
    "sndhdr": (3, 13), "spwd": (3, 13), "sunau": (3, 13), "telnetlib": (3, 13),
    "uu": (3, 13), "xdrlib": (3, 13),
    "_compression": (3, 14),
}

_TOC_PENDING = object()   # FLAG_REF ile ayrılmış ama henüz tamamlanmamış konteyner
_TOC_NULL = object()      # marshal TYPE_NULL (yalnız dict sonu)


class PyzFormatError(ValueError):
    """PYZ başlığı ya da TOC'si çözülemedi; arşiv bütünüyle reddedilir."""


class _TocMarshalReader:
    """PYZ TOC'sinin kullandığı marshal alt kümesini okuyan kısıtlı ayrıştırıcı.

    İzinli tipler: list, tuple, dict (yalnız en üstte), str, bytes, int, bool,
    None ve FLAG_REF/TYPE_REF. code, float, set gibi başka her tip PyzFormatError verir;
    hiçbir Python nesnesi yaratılmadan önce boyutlar kalan veriyle sınanır.
    Referans sırası CPython marshal ile aynıdır: konteyner, çocuklarından önce
    kaydedilir; kendine dönen (döngüsel) referans reddedilir.
    """

    def __init__(self, data: bytes, pos: int, max_top_items: int) -> None:
        self._data = data
        self._pos = pos
        self._refs: list[Any] = []
        self._max_top_items = max_top_items
        self.truncated = False

    def _take(self, n: int) -> bytes:
        end = self._pos + n
        if n < 0 or end > len(self._data):
            raise PyzFormatError("TOC marshal verisi erken bitti")
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk

    def _i32(self) -> int:
        return struct.unpack("<i", self._take(4))[0]

    def _size(self, n: int) -> int:
        # Her öğe ve karakter en az 1 bayt: kalan veriden büyük boyut sahtedir.
        if n < 0 or n > len(self._data) - self._pos:
            raise PyzFormatError("TOC marshal boyutu geçersiz: %d" % n)
        return n

    def _reserve(self, flag: int) -> Optional[int]:
        if not flag:
            return None
        self._refs.append(_TOC_PENDING)
        return len(self._refs) - 1

    def _fill(self, slot: Optional[int], value: Any) -> None:
        if slot is not None:
            self._refs[slot] = value

    def read(self, depth: int = 0) -> Any:
        if depth > _PYZ_TOC_MAX_DEPTH:
            raise PyzFormatError("TOC iç içe derinlik sınırı aşıldı")
        code = self._take(1)[0]
        flag = code & _MARSHAL_FLAG_REF
        kind = chr(code & ~_MARSHAL_FLAG_REF)

        if kind == "r":
            idx = self._i32()
            if not 0 <= idx < len(self._refs) or self._refs[idx] is _TOC_PENDING:
                raise PyzFormatError("TOC marshal referansı geçersiz: %d" % idx)
            return self._refs[idx]
        if kind == "0":
            return _TOC_NULL
        if kind in "([)":
            return self._read_sequence(kind, flag, depth)
        if kind == "{":
            return self._read_dict(flag, depth)

        try:
            if kind == "N":
                value: Any = None
            elif kind in "TF":
                value = kind == "T"
            elif kind == "i":
                value = self._i32()
            elif kind == "l":
                value = self._read_long()
            elif kind in "ut":
                value = self._take(self._size(self._i32())).decode("utf-8", "surrogatepass")
            elif kind in "aA":
                value = self._take(self._size(self._i32())).decode("latin-1")
            elif kind in "zZ":
                value = self._take(self._take(1)[0]).decode("latin-1")
            elif kind == "s":
                value = self._take(self._size(self._i32()))
            else:
                raise PyzFormatError("TOC'de izin verilmeyen marshal tipi: %r" % kind)
        except UnicodeDecodeError as exc:
            raise PyzFormatError("TOC dizgesi çözülemedi: %s" % exc) from None
        if flag:
            self._refs.append(value)
        return value

    def _read_sequence(self, kind: str, flag: int, depth: int) -> Any:
        n = self._size(self._take(1)[0] if kind == ")" else self._i32())
        if depth > 0 and n > _PYZ_TOC_MAX_INNER_ITEMS:
            raise PyzFormatError("TOC iç öğesi beklenenden büyük: %d" % n)
        count = n
        if depth == 0 and n > self._max_top_items:
            self.truncated = True
            count = self._max_top_items
        slot = self._reserve(flag)
        items = []
        for _ in range(count):
            item = self.read(depth + 1)
            if item is _TOC_NULL:
                raise PyzFormatError("TOC dizisinde beklenmeyen NULL")
            items.append(item)
        value: Any = items if kind == "[" else tuple(items)
        self._fill(slot, value)
        return value

    def _read_dict(self, flag: int, depth: int) -> list[tuple[Any, Any]]:
        # Eski TOC'ler dict olabilir; yalnız en üst düzeyde kabul edilir ve
        # (anahtar, değer) çiftleri listesi olarak döner (liste TOC ile aynı biçim).
        if depth != 0:
            raise PyzFormatError("TOC'de iç içe dict beklenmiyor")
        slot = self._reserve(flag)
        pairs: list[tuple[Any, Any]] = []
        while True:
            key = self.read(depth + 1)
            if key is _TOC_NULL:
                break
            if len(pairs) >= self._max_top_items:
                self.truncated = True
                break
            value = self.read(depth + 1)
            if value is _TOC_NULL:
                raise PyzFormatError("TOC dict değeri NULL")
            pairs.append((key, value))
        self._fill(slot, pairs)
        return pairs

    def _read_long(self) -> int:
        n = self._i32()
        if abs(n) > _PYZ_TOC_MAX_LONG_DIGITS:
            raise PyzFormatError("TOC tamsayısı çok büyük (%d basamak)" % n)
        value = 0
        for i in range(abs(n)):
            digit = struct.unpack("<H", self._take(2))[0]
            if digit >= 1 << 15:
                raise PyzFormatError("TOC tamsayı basamağı aralık dışı")
            value |= digit << (15 * i)
        return -value if n < 0 else value


@dataclass
class PyzEntry:
    """Doğrulanmış PYZ TOC girdisi (gövde henüz açılmadı)."""
    name: str
    typecode: int
    offset: int
    length: int


@dataclass
class PyzArchive:
    """PYZ başlığı + TOC ayrıştırma sonucu."""
    python_magic: bytes
    python_version: Optional[str]      # magic bilinen bir sürüme karşılık geliyorsa
    crypt_flag: int                    # başlığın 12. baytı (3.6-5.13'te 1 = şifreli)
    entries: list[PyzEntry] = field(default_factory=list)
    rejected: dict[str, int] = field(default_factory=dict)   # neden -> sayı
    toc_truncated: bool = False

    @property
    def encrypted(self) -> bool:
        return self.crypt_flag == 1


def _bump(counter: dict[str, int], reason: str, n: int = 1) -> None:
    counter[reason] = counter.get(reason, 0) + n


def _is_safe_pyz_module_name(name: str) -> bool:
    """Modül adı güvenle tek bir dosya adına (``<ad>.pyc``) çevrilebilir mi?

    Her noktalı bileşen Python tanımlayıcısı olmalı. Tanımlayıcı '/', '\\',
    NUL, boşluk içeremez ve boş olamaz; böylece '..', mutlak yol ve ayırıcı
    içeren adlar dışarıda kalır. Windows ayrılmış adları mevcut CArchive
    politikasıyla aynı şekilde reddedilir.
    """
    if not name:
        return False
    if len((name + ".pyc").encode("utf-8", "surrogatepass")) > _PYZ_MAX_NAME_BYTES:
        return False
    if not all(part.isidentifier() for part in name.split(".")):
        return False
    return not _is_windows_reserved(name + ".pyc")


def _validate_pyz_toc_item(item: Any, data_len: int) -> tuple[Optional[PyzEntry], str]:
    """TOC öğesini doğrula: (girdi, "") ya da (None, ret nedeni)."""
    if not (isinstance(item, (tuple, list)) and len(item) == 2):
        return None, "bad_toc_item"
    name, meta = item
    if not (isinstance(name, str) and isinstance(meta, (tuple, list)) and len(meta) == 3):
        return None, "bad_toc_item"
    # bool int'in alt sınıfı; tip tam olarak int olmalı.
    if not all(type(v) is int for v in meta):
        return None, "bad_toc_item"
    typecode, offset, length = meta
    if typecode == PYZ_ITEM_DATA:
        return None, "data_entry"
    if typecode not in _PYZ_CODE_TYPECODES:
        return None, "unknown_typecode"
    if not _is_safe_pyz_module_name(name):
        return None, "unsafe_name"
    if offset < 0 or length < 0 or offset + length > data_len:
        return None, "bad_range"
    return PyzEntry(name=name, typecode=typecode, offset=offset, length=length), ""


def parse_pyz(data: bytes, *, max_entries: Optional[int] = None) -> PyzArchive:
    """PYZ başlığını ve TOC'sini oku; gövdeleri AÇMAZ.

    Args:
        data: PYZ arşivinin tamamı.
        max_entries: TOC girdi üst sınırı (varsayılan
            ``PyInstallerExtractor.MAX_TOC_ENTRIES``); aşılırsa ilk ``max_entries``
            girdi alınır ve ``toc_truncated`` işaretlenir.

    Raises:
        PyzFormatError: magic yok, TOC ofseti dosya dışında ya da TOC çözülemedi.
    """
    if max_entries is None:
        max_entries = PyInstallerExtractor.MAX_TOC_ENTRIES
    if len(data) < _PYZ_HEADER_SIZE or data[:4] != PYZ_MAGIC:
        raise PyzFormatError("PYZ magic bulunamadı")
    python_magic = bytes(data[4:8])
    toc_offset = struct.unpack("!i", data[8:12])[0]
    if not _PYZ_HEADER_SIZE <= toc_offset < len(data):
        raise PyzFormatError("TOC ofseti dosya dışında: %d" % toc_offset)
    # Bayrak baytı ancak TOC başlıktan sonra başlıyorsa başlığa aittir.
    crypt_flag = data[_PYZ_CRYPT_FLAG_OFFSET] if toc_offset > _PYZ_CRYPT_FLAG_OFFSET else 0

    reader = _TocMarshalReader(data, toc_offset, max_entries)
    toc = reader.read()
    if not isinstance(toc, (list, tuple)):
        raise PyzFormatError("TOC liste ya da dict değil")

    archive = PyzArchive(
        python_magic=python_magic,
        python_version=version_from_pyc_bytes(python_magic),
        crypt_flag=crypt_flag,
        toc_truncated=reader.truncated,
    )
    if reader.truncated:
        logger.warning(
            "PYZ TOC girdi sayısı %d sınırını aştı; ilk %d girdi alındı (DoS koruma)",
            max_entries, max_entries,
        )
    index_by_name: dict[str, int] = {}
    for item in toc:
        entry, reason = _validate_pyz_toc_item(item, len(data))
        if entry is None:
            _bump(archive.rejected, reason)
            continue
        # PyInstaller TOC'yi dict(...) ile açar: aynı ad tekrar ederse sonraki kazanır.
        if entry.name in index_by_name:
            archive.entries[index_by_name[entry.name]] = entry
            _bump(archive.rejected, "duplicate_name")
            continue
        index_by_name[entry.name] = len(archive.entries)
        archive.entries.append(entry)
    return archive


def _inflate_pyz_entry(raw: bytes, limit: int) -> tuple[Optional[bytes], str, int]:
    """zlib gövdesini en fazla ``limit`` bayta aç: (veri | None, ret nedeni, üretilen bayt).

    ``safe_zlib_decompress`` ile aynı akışlı yöntem: ``max_length`` ile çıktı
    ``limit + 1`` baytta kesilir, bomba belleği şişiremez. Farkı: bozuk akış ile
    sınır aşımını ayrı raporlar ve reddedilen girdide harcanan açma işini de
    döndürür (çağıran toplam bütçeden düşer). Gövde ``_PYZ_INFLATE_CHUNK``
    dilimlerle beslenir; hata veren dilimin çıktısı sayılamaz.
    """
    decomp = zlib.decompressobj()
    out = bytearray()
    view = memoryview(raw)
    try:
        for start in range(0, len(view), _PYZ_INFLATE_CHUNK):
            out += decomp.decompress(
                view[start:start + _PYZ_INFLATE_CHUNK], limit + 1 - len(out),
            )
            if len(out) > limit or decomp.unconsumed_tail:
                return None, "too_large", len(out)
            if decomp.eof:
                break  # akış sonrası artık bayt yok sayılır (zlib.decompress gibi)
        out += decomp.flush()
    except zlib.error:
        return None, "corrupt_zlib", len(out)
    if len(out) > limit:
        return None, "too_large", len(out)
    if not decomp.eof:
        return None, "corrupt_zlib", len(out)   # kesik akış
    return bytes(out), "", len(out)


def _version_tuple(version: Optional[str]) -> Optional[tuple[int, int]]:
    if not version:
        return None
    parts = version.split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return None


def _is_stdlib_top_level(top: str, version: Optional[tuple[int, int]]) -> bool:
    """``top`` hedef Python sürümünde stdlib üst düzey modülü mü?"""
    target = version or (sys.version_info.major, sys.version_info.minor)
    added = _STDLIB_ADDED_IN.get(top)
    removed = _STDLIB_REMOVED_IN.get(top)
    if added is not None or removed is not None:
        return (added is None or target >= added) and (removed is None or target < removed)
    return top in sys.stdlib_module_names


def classify_pyz_module(name: str, python_version: Optional[str] = None) -> str:
    """PYZ modülünün decompile politikası kategorisi.

    - ``"pyinstaller"``: PyInstaller'ın kendi modülleri (pyimod*, pyiboot*, pyi_*, _pyi_*)
    - ``"stdlib"``: hedef sürümün standart kütüphanesi (bkz. ``_is_stdlib_top_level``)
    - ``"user"``: geri kalan her şey (uygulama + üçüncü parti) -> decompile zinciri

    Yalnız ada bakar: stdlib ile aynı adı taşıyan bir kullanıcı modülü "stdlib"
    sayılır (çıkarılır ve listelenir ama decompile edilmez).
    """
    top = name.split(".", 1)[0]
    if top.startswith(_PYINSTALLER_MODULE_PREFIXES):
        return "pyinstaller"
    if _is_stdlib_top_level(top, _version_tuple(python_version)):
        return "stdlib"
    return "user"


def unique_casefold_name(stem: str, used: set[str]) -> str:
    """``stem``'i ``used`` içinde tekil yap: çakışırsa ``stem~N`` (N >= 2).

    Karşılaştırma NFC + casefold ile yapılır: macOS/Windows dosya sistemleri
    harf duyarsız, macOS ayrıca Unicode biçimini eşitler; "Foo" ile "foo" aynı
    dosyaya yazılıp biri sessizce kaybolurdu. '~' tanımlayıcıda geçemediği için
    ek, gerçek bir modül adıyla çakışmaz.
    """
    key = unicodedata.normalize("NFC", stem).casefold()
    if key not in used:
        used.add(key)
        return stem
    k = 2
    while "%s~%d" % (key, k) in used:
        k += 1
    used.add("%s~%d" % (key, k))
    return "%s~%d" % (stem, k)


def _write_pyz_member(members_dir: Path, filename: str, payload: bytes) -> Optional[Path]:
    """Tek bileşenli, doğrulanmış dosya adını ``members_dir`` altına yaz (symlink izlemez)."""
    path = members_dir / filename
    try:
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
    except OSError as exc:
        logger.warning("PYZ modülü yazılamadı (%s): %s", filename, exc)
        return None
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
    except OSError as exc:
        logger.warning("PYZ modülü yazılamadı (%s): %s", filename, exc)
        return None
    return path


def extract_pyz_modules(
    pyz_data: bytes,
    members_dir: Path,
    *,
    archive_name: str,
    max_total_size: int,
    max_entries: Optional[int] = None,
    max_entry_size: int = _MAX_PYINSTALLER_DECOMPRESS,
    crypto_key_present: bool = False,
) -> tuple[list[ExtractedFile], dict[str, Any]]:
    """PYZ'deki code girdilerini başlığı onarılmış ``.pyc`` olarak ``members_dir``'e yaz.

    Güvenilmeyen veri: TOC kısıtlı ayrıştırıcıyla okunur; girdi sayısı, tek girdi
    ve toplam açılmış boyut sınırlanır; bozuk zlib/marshal girdisi atlanır ve
    sayılır. Şifreli PYZ açılmaz, raporlanır.

    Returns:
        (ExtractedFile listesi, rapor). Her dosyanın metadata'sında
        ``pyz_category`` (user/stdlib/pyinstaller) decompile politikasını taşır.
    """
    runtime = "%d.%d" % (sys.version_info.major, sys.version_info.minor)
    report: dict[str, Any] = {
        "archive": archive_name,
        "python_magic": None,
        "python_version": None,
        "encrypted": False,
        "encryption_evidence": [],
        "toc_entries": 0,
        "toc_truncated": False,
        "modules_extracted": 0,
        "bytes_inflated": 0,          # reddedilenlerde harcanan açma işi dahil
        "rejected": {},
        "stdlib_basis": {"runtime_python": runtime, "target_python": None},
        "error": None,
    }
    try:
        archive = parse_pyz(pyz_data, max_entries=max_entries)
    except PyzFormatError as exc:
        report["error"] = "PYZ okunamadı: %s" % exc
        logger.warning("PYZ okunamadı (%s): %s", archive_name, exc)
        return [], report

    report["python_magic"] = archive.python_magic.hex()
    report["python_version"] = archive.python_version
    report["stdlib_basis"]["target_python"] = archive.python_version
    report["toc_entries"] = len(archive.entries)
    report["toc_truncated"] = archive.toc_truncated
    rejected: dict[str, int] = dict(archive.rejected)
    report["rejected"] = rejected
    evidence: list[str] = report["encryption_evidence"]
    if archive.crypt_flag not in (0, 1):
        report["crypt_flag"] = archive.crypt_flag
    if crypto_key_present:
        evidence.append("CArchive'de pyimod00_crypto_key modülü var")

    if archive.encrypted:
        # TOC şifresiz (yalnız gövdeler şifreli): adlar yine de listelenir.
        evidence.append("PYZ başlığında şifreleme bayrağı = 1")
        report["encrypted"] = True
        report["encrypted_module_names"] = [e.name for e in archive.entries]
        _bump(rejected, "encrypted", len(archive.entries))
        return [], report

    if members_dir.is_symlink():
        report["error"] = "PYZ çıktı dizini symlink, yazılmadı: %s" % members_dir
        return [], report
    members_dir.mkdir(parents=True, exist_ok=True)

    version = archive.python_version
    extracted: list[ExtractedFile] = []
    used_names: set[str] = set()
    # Toplam bütçe açılan HER baytı sayar (reddedilen girdide harcanan iş dahil):
    # aksi halde binlerce "sınırı aşan" girdi, her biri limit kadar açılıp CPU'yu
    # tüketebilirdi.
    total = 0
    for entry in archive.entries:
        remaining = max_total_size - total
        if remaining <= 0:
            _bump(rejected, "total_limit")
            continue
        limit = min(max_entry_size, remaining)
        raw = pyz_data[entry.offset:entry.offset + entry.length]
        body, reason, produced = _inflate_pyz_entry(raw, limit)
        total += produced
        if body is None:
            if reason == "too_large" and limit < max_entry_size:
                # Bağlayıcı olan toplam bütçe (zip-bomb): bütçe bitti, kalanlar atlanır.
                reason = "total_limit"
                logger.warning(
                    "PYZ toplam açılmış boyut sınırı (%d bayt) aşıldı; kalan girdiler atlanıyor",
                    max_total_size,
                )
            _bump(rejected, reason)
            continue
        # Gövde bir code nesnesinin marshal'ı olmalı (FLAG_REF'li ya da değil).
        # Unmarshal EDİLMEZ; tam ayrıştırma pycdc/pycdas alt sürecinde.
        if not body or (body[0] & ~_MARSHAL_FLAG_REF) != _MARSHAL_TYPE_CODE:
            _bump(rejected, "bad_marshal")
            continue
        repaired = repair_pyc_header(body, version)
        payload = repaired if repaired is not None else body
        path = _write_pyz_member(
            members_dir, unique_casefold_name(entry.name, used_names) + ".pyc", payload,
        )
        if path is None:
            _bump(rejected, "write_failed")
            continue
        extracted.append(ExtractedFile(
            path=path,
            original_name=entry.name,
            file_type="pyc",
            size=len(payload),
            metadata={
                "pyz_module": True,
                "pyz_archive": archive_name,
                "pyz_typecode": entry.typecode,
                "is_package": entry.typecode in (PYZ_ITEM_PKG, PYZ_ITEM_NSPKG),
                "pyz_category": classify_pyz_module(entry.name, version),
                "pyc_header": "pyz_magic" if repaired is not None else "none",
            },
        ))

    report["bytes_inflated"] = total
    report["modules_extracted"] = len(extracted)
    # Anahtar modülü var ama hiçbir gövde zlib olarak açılmadıysa: bayrağı
    # silinmiş şifreli arşiv (başlık bayrağı olmadan çıkarım).
    if crypto_key_present and not extracted and rejected.get("corrupt_zlib"):
        evidence.append("hiçbir girdi zlib olarak açılmadı")
        report["encrypted"] = True
    return extracted, report


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

    # Bytecode taşıyan CArchive girdileri (.pyc olarak çıkarılır). python_binary'nin
    # static modül envanteri de bunu kullanır (tek kaynak).
    CODE_TYPE_NAMES = frozenset({"SCRIPT", "MODULE", "MODULE_PACKAGE"})

    # v1.14.5 GUVENLIK: TOC DoS koruma sabitleri.
    #
    # Saldiri vektoru 1 (CPU DoS):
    #   raw_entry_len < 18 olursa header tamamlanmis ama loop sadece 1 byte
    #   ilerleyebilir (hatta 0 da olabilir). 100MB binary'de ~100M iterasyon
    #   = saatlerce CPU + bellekte milyarlarca dict. Eski kod sadece
    #   `raw_entry_len == 0` icin break yapiyordu; <18 ile sonsuz dongu.
    #   FIX: header sigmayan boyut = malformed -> break.
    #
    # Saldiri vektoru 2 (Memory DoS):
    #   Saldirgan TOC alanini milyonlarca kucuk gecerli entry ile
    #   doldurabilir. Her entry 18+isim byte = ~24 byte; 100MB TOC ~4M entry
    #   uretir; her entry icin Python dict ~300+ byte = 1.2GB+ RAM.
    #   FIX: hard cap 100k entry; asilirsa warning + break.
    MAX_TOC_ENTRIES = 100_000
    MIN_TOC_ENTRY_HEADER_BYTES = 18

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

        # Cookie + paket başlangıcı: tek kaynak locate_pyinstaller_archive (son MEI
        # magic'i; pkg_start = cookie - toc_offset - toc_length, cookie boyutundan bağımsız).
        try:
            toc_info = locate_pyinstaller_archive(data)
        except Exception as exc:
            return UnpackResult(
                success=False,
                packing_type=PackingType.PYINSTALLER,
                errors=["Cookie parse hatasi: %s" % exc],
                duration_seconds=time.monotonic() - start,
                output_dir=output_dir,
            )
        if toc_info is None:
            return UnpackResult(
                success=False,
                packing_type=PackingType.PYINSTALLER,
                errors=["PyInstaller cookie bulunamadi"],
                duration_seconds=time.monotonic() - start,
                output_dir=output_dir,
            )
        pkg_start = toc_info["pkg_start"]

        # TOC'u parse et
        toc_entries = self._parse_toc(data, toc_info["toc_start"], toc_info["toc_length"])

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

        # PYZ (ZlibArchive): kullanıcı modüllerinin çoğu buradadır; CArchive
        # yalnız ham blobu verir, içindeki modüller ayrıca açılır.
        crypto_key_present = any(
            e.get("name") == _PYI_CRYPTO_KEY_MODULE for e in toc_entries
        )
        extracted.extend(
            self._extract_pyz_archives(extracted, output_dir, crypto_key_present, errors)
        )

        # .pyc dosyalarini decompile etmeye calis. PYZ'nin stdlib/PyInstaller
        # modülleri politika gereği yalnız çıkarılır (bkz. classify_pyz_module).
        pyc_files = [
            ef for ef in extracted
            if ef.file_type == "pyc" and ef.metadata.get("pyz_category", "user") == "user"
        ]
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

    def _extract_pyz_archives(
        self,
        extracted: list[ExtractedFile],
        output_dir: Path,
        crypto_key_present: bool,
        errors: list[str],
    ) -> list[ExtractedFile]:
        """CArchive'den çıkan PYZ bloblarını aç (``<ad>_extracted/`` altına).

        Her PYZ'nin raporu kendi ExtractedFile'ının ``metadata["pyz"]`` alanına
        yazılır. Toplam açılmış boyut bütçesi (``SecurityConfig.
        max_archive_extract_size``) tüm PYZ arşivleri arasında paylaşılır.
        """
        members: list[ExtractedFile] = []
        budget = self.config.security.max_archive_extract_size
        output_root = output_dir.resolve()
        for ef in list(extracted):
            # CArchive 'z' girdisi (TOC_TYPES'ta "ZIPFILE"); içerik magic ile doğrulanır.
            if ef.metadata.get("type_name") != "ZIPFILE":
                continue
            try:
                pyz_data = ef.path.read_bytes()
            except OSError as exc:
                errors.append("PYZ okunamadı (%s): %s" % (ef.original_name, exc))
                continue
            if not pyz_data.startswith(PYZ_MAGIC):
                continue
            members_dir = ef.path.with_name(ef.path.name + "_extracted")
            try:
                members_dir.resolve().relative_to(output_root)
            except ValueError:
                errors.append("PYZ çıktı dizini çıktı kökü dışında: %s" % members_dir)
                continue
            try:
                files, report = extract_pyz_modules(
                    pyz_data, members_dir,
                    archive_name=ef.original_name,
                    max_total_size=budget,
                    crypto_key_present=crypto_key_present,
                )
            except Exception as exc:  # beklenmeyen hata CArchive sonuçlarını düşürmesin
                logger.debug("PYZ açma hatası (%s)", ef.original_name, exc_info=True)
                errors.append("PYZ açma hatası (%s): %s" % (ef.original_name, exc))
                continue
            budget -= report["bytes_inflated"]
            ef.metadata["pyz"] = report
            if report["error"]:
                errors.append(report["error"])
            if report["encrypted"]:
                errors.append(
                    "PYZ şifreli (PyInstaller <6.0 bytecode şifrelemesi): "
                    "%d modülün adı listelendi, içeriği çözülmedi (%s)"
                    % (report["toc_entries"], ef.original_name)
                )
            members.extend(files)
        return members

    @staticmethod
    def _parse_cookie(data: bytes, offset: int) -> dict[str, Any]:
        """PyInstaller cookie struct'ini parse et.

        Args:
            data: Binary verisi.
            offset: Cookie baslangic offset'i.

        Returns:
            dict: Cookie bilgileri.
        """
        return parse_pyinstaller_cookie(data, offset)

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
        entries: list[dict[str, Any]] = []
        pos = toc_start
        end = toc_start + toc_length

        # v1.14.5 GUVENLIK: lokal alias (her iterasyonda attribute lookup'i
        # gereksiz; ayrica future override icin sinif uzerinden okuma).
        max_entries = PyInstallerExtractor.MAX_TOC_ENTRIES
        min_header = PyInstallerExtractor.MIN_TOC_ENTRY_HEADER_BYTES

        while pos < end and pos < len(data):
            # En az 18 byte header gerekli
            if pos + min_header > len(data):
                break

            # v1.14.5 GUVENLIK: entry sayisi cap. Saldirgan kucuk entry'lerle
            # bellek tuketmesin diye hard limit; gercek PyInstaller binary'leri
            # tipik 1k-10k entry, 100k cok cok ustunde.
            if len(entries) >= max_entries:
                logger.warning(
                    "PyInstaller TOC entry sayisi %d limitini asti, "
                    "parser durduruldu (DoS koruma)",
                    max_entries,
                )
                break

            try:
                # PyInstaller TOC entry header (18 byte):
                #   [0:4]  entry_len (raw_entry_len, kendisini de iceren toplam uzunluk)
                #   [4:8]  entry_offset
                #   [8:12] data_length
                #   [12:16] uncompressed_length
                #   [16]   compress_flag (B)
                #   [17]   type_flag (B)
                # Format "!IIIBB" = 4+4+4+1+1 = 14 byte, 5 deger dondurur.
                entry_off, data_len, uncomp_len, cflag, tflag = struct.unpack(
                    "!IIIBB", data[pos + 4:pos + 18],
                )
                raw_entry_len = struct.unpack("!I", data[pos:pos + 4])[0]

                # v1.14.5 GUVENLIK: raw_entry_len < 18 (header sigmayan
                # boyut) -> malformed TOC. Eski kod sadece raw_entry_len==0
                # icin break atiyordu; raw_entry_len=1 durumunda 1 byte
                # ilerleyip bir sonraki "header"i 17 byte yanlis hizalanmis
                # olarak okuyordu. 100MB binary'de 100M iterasyon CPU DoS.
                if raw_entry_len < min_header:
                    logger.warning(
                        "PyInstaller TOC entry uzunlugu (%d) minimum "
                        "header'dan kucuk, parser durduruldu (malformed)",
                        raw_entry_len,
                    )
                    break

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

        # v1.14.5 GUVENLIK: symlink escape koruma (TOCTOU benzeri).
        # Senaryo: output_dir icinde onceden yerlestirilmis bir symlink
        # `foo -> /tmp/escape` varsa, `Path.write_bytes` symlink'i takip
        # ederek output_dir DISINA yazar. Path.resolve() symlink'i cozer
        # ama eger zaten cozulmus hedef output_dir disindaysa relative_to
        # zaten engeller; ANCAK aym extract calistirmasinin ilk
        # entry'si "foo" symlink'ini olusturur ve sonraki entry "foo"
        # uzerinden yazma yaparsa relative_to gecerse de write_bytes
        # symlink'i izler. En guvenli yol: hedef path symlink'se reddet.
        # Ust dizinleri (parent.parent...) de tarayip symlink varsa engelle.
        try:
            # parents iter: out_path.parent, parent.parent, ..., root.
            # output_dir'a kadar yukari git.
            output_root = output_dir.resolve()
            cursor = out_path
            for _ in range(64):  # path derinligi sonsuz olmasin
                if cursor.is_symlink():
                    logger.warning(
                        "Symlink escape engellendi (path bileseni symlink): %s",
                        name,
                    )
                    return None
                if cursor == output_root or cursor.parent == cursor:
                    break
                cursor = cursor.parent
        except OSError:
            logger.warning("Symlink kontrol hatasi, entry reddedildi: %s", name)
            return None

        out_path.parent.mkdir(parents=True, exist_ok=True)
        # v1.14.5 GUVENLIK: O_NOFOLLOW ile yazim. Hedef bir symlink ise
        # OSError (ELOOP) firlatilir. write_bytes Python 3 default'unda
        # symlink takip eder; bu yuzden manuel low-level open kullaniyoruz.
        try:
            fd = os.open(
                str(out_path),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
                0o644,
            )
        except OSError as exc:
            logger.warning(
                "Symlink/dosya yazma engellendi (%s): %s", name, exc,
            )
            return None
        try:
            os.write(fd, raw)
        finally:
            os.close(fd)

        # Dosya tipini belirle
        file_type = "data"
        type_name = entry.get("type_name", "")
        if type_name in PyInstallerExtractor.CODE_TYPE_NAMES:
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
        decompiled: list[ExtractedFile] = []

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
        errors: list[str] = []
        extracted: list[ExtractedFile] = []

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
        metadata: dict[str, list[str]] = {
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
                    # lief section.name `str | bytes`, normalize edilip kullanilir.
                    raw_name = sec.name
                    if isinstance(raw_name, bytes):
                        sec_name = raw_name.decode("utf-8", errors="replace") or "unnamed"
                    else:
                        sec_name = raw_name or "unnamed"
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
