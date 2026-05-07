"""Packer/Protector fingerprint detection modulu.

Karadul v1.13 Dalga 1 Wave 2 — `packed_binary.py` mevcut entropy/section-ratio
detection'unu **spesifik packer tespiti** ile tamamlar. Hedef: 15-25 yaygin
packer/protector/installer'i kompakt registry + 3-katman scoring ile tani.

Detection katmanlari:
1. Section name matching (en kesin, ~0.85-0.95 confidence)
2. String/version markers (~0.70-0.90 confidence)
3. Entry point byte pattern (heuristic, ~0.55-0.80 confidence)

Birden fazla katmandan eslesme (kombine evidence) confidence'i artirir
(boost: +0.05 her ek katman, max 0.99). Birden fazla packer (nested) tespit
edilebilir — ornegin Themida + UPX katmanli paketleme.

LLM YOK kurali: tum kararlar deterministic registry + heuristik.

Cross-platform:
- PE  (Windows): UPX, VMProtect, Themida, Enigma, ASPack, PECompact, MPRESS,
       FSG, MEW, NsPack, Petite, Obsidium, Confuser, PyInstaller, Nuitka
- ELF (Linux):  UPX (cross-platform), generic ELF crypters
- Mach-O (macOS): UPX cross-platform, MachOEncryptor benzeri stub'lar

Referans: DIE (Detect It Easy) JSON imza yapisi konsept olarak alinmistir,
fakat hicbir kod/veri kopyalanmamistir — sadece "section + string + entry"
3-katmanli yaklasim ortak. Bagimlilik: yok (sadece stdlib).

Kullanim:
    from karadul.analyzers.packer_fingerprint import (
        PackerFingerprintDetector, PackerFingerprint
    )

    detector = PackerFingerprintDetector(binary_path)
    fingerprints = detector.detect()
    for fp in fingerprints:
        print(f"{fp.packer_name} (conf={fp.confidence:.2f})")
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Veri sinifi
# ---------------------------------------------------------------------------

@dataclass
class PackerFingerprint:
    """Tek bir packer eslesmesi.

    Attributes:
        packer_name: "UPX", "VMProtect", "Themida", "PyInstaller", ...
        version: Tespit edilebildiyse "3.96", "v2.x"; yoksa None.
        confidence: 0.0 - 1.0 arasi guven skoru.
        evidence: Kanitlar listesi (section adlari, byte imzalari, stringler).
        category: "compressor" | "protector" | "obfuscator" | "installer" |
                  "crypter" | "vm-protector".
        platform: "pe" | "elf" | "macho" | "any".
        layers_matched: Eslesen katman sayisi (1=section/string/entry tek
                        katmandan, 2=iki katmandan, 3=tum katmanlardan).
    """
    packer_name: str
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    category: str = "unknown"
    platform: str = "any"
    layers_matched: int = 0

    def to_dict(self) -> dict:
        """JSON-serializable dict."""
        return {
            "packer_name": self.packer_name,
            "version": self.version,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "category": self.category,
            "platform": self.platform,
            "layers_matched": self.layers_matched,
        }


# ---------------------------------------------------------------------------
# Registry — Section name imzalari
# ---------------------------------------------------------------------------
#
# Her giris: section adlarinin (TUPLE) tamaminin gorulmesi gerekir.
# Tek bir section adi yeterli ise tek elemanli tuple kullan.
# Confidence: section name match'in dogal guven skoru (varsayilan 0.85).

@dataclass(frozen=True)
class _SectionRule:
    """Section name kuralı."""
    sections: tuple[str, ...]
    packer: str
    category: str
    confidence: float = 0.85
    require_all: bool = True   # True: hepsi gorulmeli; False: en az biri.
    platform: str = "pe"


_PE_SECTION_RULES: tuple[_SectionRule, ...] = (
    # UPX — UPX0 (uncompressed stub) + UPX1 (compressed payload)
    _SectionRule(("UPX0", "UPX1"), "UPX", "compressor", 0.95, True, "pe"),
    _SectionRule(("UPX2",), "UPX", "compressor", 0.70, True, "pe"),
    # VMProtect — .vmp0/.vmp1/.vmp2 (virtualization protection)
    _SectionRule((".vmp0", ".vmp1"), "VMProtect", "vm-protector", 0.92, True, "pe"),
    _SectionRule((".vmp2",), "VMProtect", "vm-protector", 0.78, True, "pe"),
    # Themida / WinLicense
    _SectionRule((".themida",), "Themida", "vm-protector", 0.92, True, "pe"),
    _SectionRule(("WinLicen",), "WinLicense", "protector", 0.90, True, "pe"),
    # Enigma Protector
    _SectionRule((".enigma1", ".enigma2"), "Enigma", "protector", 0.92, True, "pe"),
    # ASPack
    _SectionRule((".aspack", ".adata"), "ASPack", "compressor", 0.92, True, "pe"),
    _SectionRule((".aspack",), "ASPack", "compressor", 0.85, True, "pe"),
    # PECompact
    _SectionRule(("pec1", "pec2"), "PECompact", "compressor", 0.90, True, "pe"),
    _SectionRule(("PEC2",), "PECompact", "compressor", 0.78, True, "pe"),
    # MPRESS
    _SectionRule((".MPRESS1", ".MPRESS2"), "MPRESS", "compressor", 0.93, True, "pe"),
    # FSG (Fast Small Good)
    _SectionRule(("FSG!",), "FSG", "compressor", 0.85, True, "pe"),
    # MEW
    _SectionRule(("MEW",), "MEW", "compressor", 0.85, True, "pe"),
    # NsPack
    _SectionRule((".nsp0", ".nsp1"), "NsPack", "compressor", 0.92, True, "pe"),
    _SectionRule((".nsp2",), "NsPack", "compressor", 0.78, True, "pe"),
    # Petite
    _SectionRule((".petite",), "Petite", "compressor", 0.88, True, "pe"),
    # Obsidium
    _SectionRule((".obsidium",), "Obsidium", "protector", 0.90, True, "pe"),
    # Yoda's Crypter / Yoda's Protector
    _SectionRule((".yP", ".y0da"), "Yoda", "crypter", 0.88, False, "pe"),
    # tElock
    _SectionRule((".tsuarez",), "tElock", "crypter", 0.85, True, "pe"),
    # PEPACK
    _SectionRule(("PEPACK",), "PEPACK", "compressor", 0.82, True, "pe"),
    # PolyEnE
    _SectionRule(("PolyEnE",), "PolyEnE", "crypter", 0.80, True, "pe"),
    # Armadillo / SoftwarePassport
    _SectionRule((".nicode",), "Armadillo", "protector", 0.85, True, "pe"),
    # ExeStealth
    _SectionRule(("ExeS",), "ExeStealth", "protector", 0.78, True, "pe"),
    # RLPack
    _SectionRule(("RLPack",), "RLPack", "compressor", 0.82, True, "pe"),
)

_ELF_SECTION_RULES: tuple[_SectionRule, ...] = (
    # ELF UPX: eski versiyonlar UPX! magic'i baslangicta yazar; section adlari
    # UPX tarafindan rewriting sonrasi kaybolur ama p_filesz/p_memsz oranindan
    # tahmin edilebilir. Section-level fingerprint'te ELF zayif kalir; ancak
    # ".UPX_SAVED" gibi marker section'lar bazen kalir.
    _SectionRule((".UPX_SAVED",), "UPX", "compressor", 0.85, True, "elf"),
)

_MACHO_SECTION_RULES: tuple[_SectionRule, ...] = (
    # Mach-O UPX: __XHDR segment'ini yazar (UPX 4.x+).
    _SectionRule(("__XHDR",), "UPX", "compressor", 0.85, True, "macho"),
)


# ---------------------------------------------------------------------------
# Registry — String/version markers
# ---------------------------------------------------------------------------
#
# `pattern` regex'i (bytes) binary icinde aranir. Match grubunda versiyon
# yakalanabilir.

@dataclass(frozen=True)
class _StringRule:
    """String/regex kuralı."""
    pattern: bytes              # raw bytes regex
    packer: str
    category: str
    confidence: float = 0.80
    version_group: int = 0      # 0 = versiyon yok; >=1 = grup numarasi
    platform: str = "any"


_STRING_RULES: tuple[_StringRule, ...] = (
    # UPX banner
    _StringRule(rb"UPX\s+([\d\.]+)\s+Copyright", "UPX", "compressor", 0.92, 1, "any"),
    _StringRule(rb"\$Info: This file is packed with the UPX", "UPX", "compressor", 0.90, 0, "any"),
    _StringRule(rb"UPX!", "UPX", "compressor", 0.55, 0, "any"),  # zayif (false-positive olur)
    # PyInstaller
    _StringRule(rb"_MEIPASS", "PyInstaller", "installer", 0.92, 0, "any"),
    _StringRule(rb"pyiboot01_bootstrap", "PyInstaller", "installer", 0.93, 0, "any"),
    _StringRule(rb"PYZ-00\.pyz", "PyInstaller", "installer", 0.90, 0, "any"),
    _StringRule(rb"pyi-bootloader", "PyInstaller", "installer", 0.88, 0, "any"),
    # Nuitka
    _StringRule(rb"Nuitka-Scons", "Nuitka", "installer", 0.92, 0, "any"),
    _StringRule(rb"__nuitka_", "Nuitka", "installer", 0.85, 0, "any"),
    _StringRule(rb"NUITKA_PACKAGE_", "Nuitka", "installer", 0.90, 0, "any"),
    # VMProtect
    _StringRule(rb"VMProtect\s+(?:Ultimate|Professional|begin|end)", "VMProtect", "vm-protector", 0.92, 0, "pe"),
    _StringRule(rb"VMProtect\(R\)", "VMProtect", "vm-protector", 0.90, 0, "pe"),
    # Themida
    _StringRule(rb"Themida\s+v?([\d\.]+)", "Themida", "vm-protector", 0.92, 1, "pe"),
    _StringRule(rb"Themida", "Themida", "vm-protector", 0.78, 0, "pe"),
    _StringRule(rb"WinLicense", "WinLicense", "protector", 0.85, 0, "pe"),
    # Enigma
    _StringRule(rb"Enigma\s+Protector", "Enigma", "protector", 0.90, 0, "pe"),
    # Confuser / ConfuserEx (.NET obfuscator)
    _StringRule(rb"ConfusedByAttribute", "Confuser", "obfuscator", 0.92, 0, "pe"),
    _StringRule(rb"ConfuserEx", "Confuser", "obfuscator", 0.92, 0, "pe"),
    _StringRule(rb"Confuser\.Core", "Confuser", "obfuscator", 0.88, 0, "pe"),
    # .NET Reactor
    _StringRule(rb"\.NET Reactor", "DotNetReactor", "obfuscator", 0.88, 0, "pe"),
    _StringRule(rb"NetReactor", "DotNetReactor", "obfuscator", 0.78, 0, "pe"),
    # Dotfuscator
    _StringRule(rb"Dotfuscator", "Dotfuscator", "obfuscator", 0.88, 0, "pe"),
    # SmartAssembly
    _StringRule(rb"SmartAssembly\.Attributes", "SmartAssembly", "obfuscator", 0.88, 0, "pe"),
    # ASProtect
    _StringRule(rb"ASProtect\s+v?([\d\.]+)", "ASProtect", "protector", 0.90, 1, "pe"),
    _StringRule(rb"ASProtect", "ASProtect", "protector", 0.80, 0, "pe"),
    # Obsidium
    _StringRule(rb"Obsidium\s+Software", "Obsidium", "protector", 0.90, 0, "pe"),
    # Petite
    _StringRule(rb"Petite\s+v?([\d\.]+)", "Petite", "compressor", 0.88, 1, "pe"),
    # NSIS installer
    _StringRule(rb"Nullsoft\.NSIS\.exehead", "NSIS", "installer", 0.92, 0, "pe"),
    _StringRule(rb"NSIS Error", "NSIS", "installer", 0.78, 0, "pe"),
    # Inno Setup
    _StringRule(rb"Inno Setup Setup Data \(([\d\.]+)\)", "InnoSetup", "installer", 0.92, 1, "pe"),
    _StringRule(rb"Inno Setup", "InnoSetup", "installer", 0.80, 0, "pe"),
    # InstallShield
    _StringRule(rb"InstallShield", "InstallShield", "installer", 0.78, 0, "pe"),
    # WiX / MSI bootstrap
    _StringRule(rb"WixBurnHeader", "WixBurn", "installer", 0.85, 0, "pe"),
    # Electron — installer degil ama paketlenmis app
    _StringRule(rb"electron\.asar", "Electron", "installer", 0.85, 0, "any"),
    # PolyEnE / PolyMorph
    _StringRule(rb"PolyEnE\s+by\s+lifewire", "PolyEnE", "crypter", 0.90, 0, "pe"),
    # MEW
    _StringRule(rb"MEW SE 1\.[\d]+", "MEW", "compressor", 0.92, 0, "pe"),
    # FSG
    _StringRule(rb"FSG!", "FSG", "compressor", 0.65, 0, "pe"),  # zayif
)


# ---------------------------------------------------------------------------
# Registry — Entry point byte pattern (heuristic)
# ---------------------------------------------------------------------------
#
# Sadece dosya basinda/PE entry yakininda aranan kisa imzalar.
# Gercek entry point hesaplamasi pahali (PE header parse). Burada
# "ilk N byte" + "dosyada en az 1 yerde" kombo aranir; ileride PE entry
# offset'i parse edilirse confidence artirilabilir.

@dataclass(frozen=True)
class _EntryRule:
    """Entry-point/header byte pattern kuralı."""
    pattern: bytes              # ilk eslesmesi entry yakini olmali
    max_offset: int             # dosyanin ilk max_offset byte'inda olmali
    packer: str
    category: str
    confidence: float = 0.65
    platform: str = "pe"


_ENTRY_RULES: tuple[_EntryRule, ...] = (
    # UPX classic stub: 60 BE ?? ?? ?? ?? 8D BE  (PUSHAD; MOV ESI, imm32; LEA EDI)
    # Bu pattern UPX'in ana decompression stub baslangicidir (32-bit PE).
    _EntryRule(b"\x60\xbe", 0x4000, "UPX", "compressor", 0.55, "pe"),
    # ASPack stub: 60 E8 03 00 00 00 E9 EB 04 5D
    _EntryRule(b"\x60\xe8\x03\x00\x00\x00\xe9\xeb", 0x4000, "ASPack", "compressor", 0.78, "pe"),
    # FSG stub: BB ?? ?? ?? ?? BF ?? ?? ?? ??
    _EntryRule(b"\xbb", 0x2000, "FSG", "compressor", 0.30, "pe"),  # cok zayif
    # Petite stub: B8 ?? ?? ?? ?? 66 9C 60
    _EntryRule(b"\x66\x9c\x60", 0x2000, "Petite", "compressor", 0.45, "pe"),
    # MPRESS stub: imm push + jmp pattern (yaklasik)
    _EntryRule(b"\x60\xe8\x00\x00\x00\x00", 0x4000, "MPRESS", "compressor", 0.40, "pe"),
    # Themida polymorphic prologue (yaklasik): EB ?? bytes + entropy
    # Saf byte pattern Themida icin guvenilir degil; sadece zayif ipucu.
    # tElock: 60 E8 00 00 00 00 5D 81 ED
    _EntryRule(b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed", 0x4000, "tElock", "crypter", 0.78, "pe"),
)


# ---------------------------------------------------------------------------
# Yardimcilar — section name extraction
# ---------------------------------------------------------------------------

# PE Section table parser (minimal) — full parser yerine sadece adlari ariyoruz.
# Karadul'un kendi PE parser'i (`pefile`) varsa o tercih edilir; burada stdlib
# only ile manuel parse yapiyoruz ki bagimlilik patlamasin.

_PE_DOS_MAGIC = b"MZ"
_PE_NT_MAGIC = b"PE\x00\x00"
_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit BE)
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
    b"\xce\xfa\xed\xfe",  # MH_CIGAM
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC (universal)
}


def _detect_platform(data: bytes) -> str:
    """Binary platformunu tespit et: 'pe' | 'elf' | 'macho' | 'unknown'."""
    if len(data) < 4:
        return "unknown"
    if data[:2] == _PE_DOS_MAGIC:
        return "pe"
    if data[:4] == _ELF_MAGIC:
        return "elf"
    if data[:4] in _MACHO_MAGICS:
        return "macho"
    return "unknown"


def _extract_pe_sections(data: bytes) -> list[str]:
    """PE dosyasindaki section adlarini cikar.

    Manuel parse — bagimlilik yok. Hata durumunda bos liste doner.
    """
    sections: list[str] = []
    try:
        if len(data) < 0x40 or data[:2] != _PE_DOS_MAGIC:
            return sections

        # e_lfanew offset (DOS header, 0x3C)
        e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
        if e_lfanew >= len(data) - 4 or e_lfanew < 0x40:
            return sections

        if data[e_lfanew:e_lfanew + 4] != _PE_NT_MAGIC:
            return sections

        # COFF header: 4 (signature) + Machine(2) + NumSections(2) ...
        num_sections_off = e_lfanew + 4 + 2
        if num_sections_off + 2 > len(data):
            return sections
        num_sections = struct.unpack_from("<H", data, num_sections_off)[0]

        # SizeOfOptionalHeader: e_lfanew + 4 + 16 (offset 20'de COFF)
        size_opt_off = e_lfanew + 4 + 16
        if size_opt_off + 2 > len(data):
            return sections
        size_opt = struct.unpack_from("<H", data, size_opt_off)[0]

        # Section table: COFF header (24 byte) + optional header sonra
        section_table_off = e_lfanew + 4 + 20 + size_opt

        # PE specs: max 96 section gibi limit, ama biz 256'da kesip guvende olalim
        num_sections = min(num_sections, 256)

        for i in range(num_sections):
            entry_off = section_table_off + i * 40  # IMAGE_SECTION_HEADER = 40 byte
            if entry_off + 8 > len(data):
                break
            name_bytes = data[entry_off:entry_off + 8]
            # null-terminated, UTF-8/ASCII
            name = name_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            sections.append(name)
    except (struct.error, UnicodeDecodeError, IndexError) as exc:
        logger.debug("PE section parse hatasi: %s", exc)
    return sections


def _extract_elf_sections(data: bytes) -> list[str]:
    """ELF dosyasindaki section adlarini cikar (minimal parser)."""
    sections: list[str] = []
    try:
        if len(data) < 64 or data[:4] != _ELF_MAGIC:
            return sections

        # ei_class: 1=32-bit, 2=64-bit (offset 4)
        ei_class = data[4]
        # ei_data: 1=little, 2=big (offset 5)
        ei_data = data[5]
        endian = "<" if ei_data == 1 else ">"

        if ei_class == 1:
            # Elf32_Ehdr: e_shoff @ 32, e_shentsize @ 46, e_shnum @ 48, e_shstrndx @ 50
            e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 46)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 48)[0]
            e_shstrndx = struct.unpack_from(endian + "H", data, 50)[0]
            sh_name_size, sh_offset_size = 4, 4
        elif ei_class == 2:
            # Elf64_Ehdr: e_shoff @ 40, e_shentsize @ 58, e_shnum @ 60, e_shstrndx @ 62
            e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 58)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 60)[0]
            e_shstrndx = struct.unpack_from(endian + "H", data, 62)[0]
            sh_name_size, sh_offset_size = 4, 8
        else:
            return sections

        if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
            return sections
        e_shnum = min(e_shnum, 256)

        # shstrtab: header at index e_shstrndx, sh_offset @ +16 (32) or +24 (64)
        shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize
        if shstr_hdr_off + e_shentsize > len(data):
            return sections

        if ei_class == 1:
            shstr_offset = struct.unpack_from(endian + "I", data, shstr_hdr_off + 16)[0]
            shstr_size = struct.unpack_from(endian + "I", data, shstr_hdr_off + 20)[0]
        else:
            shstr_offset = struct.unpack_from(endian + "Q", data, shstr_hdr_off + 24)[0]
            shstr_size = struct.unpack_from(endian + "Q", data, shstr_hdr_off + 32)[0]

        if shstr_offset + shstr_size > len(data):
            return sections

        shstrtab = data[shstr_offset:shstr_offset + shstr_size]

        for i in range(e_shnum):
            entry_off = e_shoff + i * e_shentsize
            if entry_off + 4 > len(data):
                break
            sh_name_idx = struct.unpack_from(endian + "I", data, entry_off)[0]
            if sh_name_idx >= len(shstrtab):
                continue
            name_end = shstrtab.find(b"\x00", sh_name_idx)
            if name_end < 0:
                name_end = len(shstrtab)
            name = shstrtab[sh_name_idx:name_end].decode("utf-8", errors="replace")
            if name:
                sections.append(name)
    except (struct.error, UnicodeDecodeError, IndexError) as exc:
        logger.debug("ELF section parse hatasi: %s", exc)
    return sections


def _extract_macho_sections(data: bytes) -> list[str]:
    """Mach-O segment/section adlarini cikar.

    LC_SEGMENT (0x1) ve LC_SEGMENT_64 (0x19) komutlarini gezer.
    Universal/fat binary destegi yok (cagiranin slice etmesi beklenir).
    """
    sections: list[str] = []
    try:
        if len(data) < 32:
            return sections
        magic = data[:4]
        if magic not in _MACHO_MAGICS or magic == b"\xca\xfe\xba\xbe":
            # FAT: tek-arch slicing yapmiyoruz
            return sections

        is_64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
        is_le = magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
        endian = "<" if is_le else ">"

        # mach_header: magic(4) cputype(4) cpusubtype(4) filetype(4) ncmds(4) sizeofcmds(4) flags(4) [reserved(4) for 64]
        ncmds = struct.unpack_from(endian + "I", data, 16)[0]
        ncmds = min(ncmds, 1024)
        cmds_off = 32 if is_64 else 28

        for _ in range(ncmds):
            if cmds_off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(endian + "II", data, cmds_off)
            if cmdsize == 0 or cmds_off + cmdsize > len(data):
                break

            if cmd == 0x1 or cmd == 0x19:  # LC_SEGMENT / LC_SEGMENT_64
                # segname @ +8 (16 byte)
                segname_bytes = data[cmds_off + 8:cmds_off + 24]
                segname = segname_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                if segname:
                    sections.append(segname)
            cmds_off += cmdsize
    except (struct.error, UnicodeDecodeError, IndexError) as exc:
        logger.debug("Mach-O section parse hatasi: %s", exc)
    return sections


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class PackerFingerprintDetector:
    """3-katmanli packer fingerprint tarayicisi.

    Katmanlar:
        1. Section name matching (`detect_by_sections`)
        2. String/regex marker tarama (`detect_by_strings`)
        3. Entry-point byte pattern (`detect_by_entry_pattern`)

    `detect()` uc katmani da calistirip ayni packer'i farkli katmanlardan
    bulduysa kanit'lari birlestirir ve confidence'i boost eder.
    """

    # Maksimum okunacak dosya boyutu (OOM koruma). 200 MB; uzeri ihtimal disi.
    MAX_READ_BYTES = 200 * 1024 * 1024
    # String tarama icin maksimum byte (ilk N byte zaten cogu marker icin yeterli)
    MAX_STRING_SCAN_BYTES = 16 * 1024 * 1024

    # Confidence boost'u: ek katman basina puan (max 0.99'a clamp)
    MULTI_LAYER_BOOST = 0.05
    MAX_CONFIDENCE = 0.99

    def __init__(self, target: Path | str, *, _data: Optional[bytes] = None):
        """Initialize.

        Args:
            target: Binary dosya yolu. (BinaryTarget alternatif: testlerde
                    `_data` parametresi enjekte edilebilir.)
            _data: Test/sandbox amacli onceden yuklu byte data (file IO atla).
        """
        self.target_path = Path(target) if not isinstance(target, Path) else target
        self._data: Optional[bytes] = _data
        self._sections: Optional[list[str]] = None
        self._platform: Optional[str] = None

    # ---- veri yukleyici ---------------------------------------------------

    def _load_data(self) -> bytes:
        if self._data is not None:
            return self._data
        if not self.target_path.is_file():
            logger.warning("Hedef dosya bulunamadi: %s", self.target_path)
            return b""
        try:
            with open(self.target_path, "rb") as f:
                # OOM koruma: max okuma sinirla
                self._data = f.read(self.MAX_READ_BYTES)
            return self._data
        except OSError as exc:
            logger.warning("Dosya okuma hatasi: %s", exc)
            return b""

    def _get_platform(self) -> str:
        if self._platform is None:
            self._platform = _detect_platform(self._load_data())
        return self._platform

    def _get_sections(self) -> list[str]:
        if self._sections is not None:
            return self._sections
        data = self._load_data()
        plat = self._get_platform()
        if plat == "pe":
            self._sections = _extract_pe_sections(data)
        elif plat == "elf":
            self._sections = _extract_elf_sections(data)
        elif plat == "macho":
            self._sections = _extract_macho_sections(data)
        else:
            self._sections = []
        return self._sections

    # ---- katman 1: section names -----------------------------------------

    def detect_by_sections(self) -> list[PackerFingerprint]:
        """Section adlarindan packer eslestir.

        Returns:
            list: Eslesmis packer fingerprint'leri (boost edilmemis).
        """
        plat = self._get_platform()
        sections = self._get_sections()
        if not sections:
            return []

        # Lower-case karsilastirma (PE'de section adlari case-sensitive ama
        # bazi packer'lar yuklerken bozuyor; tam eslesme + case-insensitive
        # fallback iki seviyede yapilir).
        section_set = set(sections)
        section_set_ci = {s.lower() for s in sections}

        rules: tuple[_SectionRule, ...]
        if plat == "pe":
            rules = _PE_SECTION_RULES
        elif plat == "elf":
            rules = _ELF_SECTION_RULES
        elif plat == "macho":
            rules = _MACHO_SECTION_RULES
        else:
            return []

        findings: list[PackerFingerprint] = []
        for rule in rules:
            if rule.require_all:
                hits = [s for s in rule.sections if s in section_set or s.lower() in section_set_ci]
                if len(hits) != len(rule.sections):
                    continue
                evidence = [f"section adi: {s}" for s in rule.sections]
            else:
                hits = [s for s in rule.sections if s in section_set or s.lower() in section_set_ci]
                if not hits:
                    continue
                evidence = [f"section adi: {s}" for s in hits]

            findings.append(PackerFingerprint(
                packer_name=rule.packer,
                version=None,
                confidence=rule.confidence,
                evidence=evidence,
                category=rule.category,
                platform=rule.platform,
                layers_matched=1,
            ))
        return findings

    # ---- katman 2: strings -----------------------------------------------

    def detect_by_strings(self) -> list[PackerFingerprint]:
        """Bilinen string/version marker'larini ara."""
        data = self._load_data()
        if not data:
            return []
        scan_buf = data[:self.MAX_STRING_SCAN_BYTES]
        plat = self._get_platform()

        findings: list[PackerFingerprint] = []
        seen: set[tuple[str, str]] = set()  # (packer, evidence) dedup

        for rule in _STRING_RULES:
            if rule.platform != "any" and plat != "unknown" and rule.platform != plat:
                continue
            try:
                m = re.search(rule.pattern, scan_buf)
            except re.error as exc:
                logger.warning("Regex hatasi (%r): %s", rule.pattern, exc)
                continue
            if not m:
                continue
            version: Optional[str] = None
            if rule.version_group >= 1 and m.lastindex and m.lastindex >= rule.version_group:
                try:
                    version = m.group(rule.version_group).decode("utf-8", errors="replace")
                except (AttributeError, UnicodeDecodeError):
                    version = None

            ev_text = "string: %s" % m.group(0)[:64].decode("utf-8", errors="replace")
            key = (rule.packer, ev_text)
            if key in seen:
                continue
            seen.add(key)

            findings.append(PackerFingerprint(
                packer_name=rule.packer,
                version=version,
                confidence=rule.confidence,
                evidence=[ev_text],
                category=rule.category,
                platform=plat if plat != "unknown" else rule.platform,
                layers_matched=1,
            ))
        return findings

    # ---- katman 3: entry-point byte pattern ------------------------------

    def detect_by_entry_pattern(self) -> list[PackerFingerprint]:
        """Dosya basinda kisa entry-point imzalari ara.

        Not: PE entry RVA hesaplamasi simdilik yapilmiyor; sadece dosyanin ilk
        `max_offset` byte'inda pattern aranir. Ileride PE parse ile tam entry
        offset'inde dogrulama yapilirsa confidence artirilabilir.
        """
        data = self._load_data()
        if not data:
            return []
        plat = self._get_platform()

        findings: list[PackerFingerprint] = []
        seen: set[str] = set()

        for rule in _ENTRY_RULES:
            if rule.platform != "any" and plat != "unknown" and rule.platform != plat:
                continue
            search_window = data[:rule.max_offset]
            idx = search_window.find(rule.pattern)
            if idx < 0:
                continue
            if rule.packer in seen:
                continue
            seen.add(rule.packer)
            findings.append(PackerFingerprint(
                packer_name=rule.packer,
                version=None,
                confidence=rule.confidence,
                evidence=[f"entry pattern @0x{idx:x}: {rule.pattern.hex()}"],
                category=rule.category,
                platform=plat if plat != "unknown" else rule.platform,
                layers_matched=1,
            ))
        return findings

    # ---- birlesik detect() -----------------------------------------------

    def detect(self) -> list[PackerFingerprint]:
        """Uc katman + birlesik scoring.

        Ayni packer'i farkli katmanlardan bulduysak:
        - kanit listelerini birlestir (set semantik)
        - confidence = max(layer confidences) + (extra_layers * boost)
        - layers_matched = eslesen katman sayisi (1-3)

        Returns:
            list: Confidence'a gore azalan sirada packer fingerprint listesi.
        """
        layer_results = [
            self.detect_by_sections(),
            self.detect_by_strings(),
            self.detect_by_entry_pattern(),
        ]

        # packer adina gore aggregate
        merged: dict[str, PackerFingerprint] = {}
        for layer_idx, results in enumerate(layer_results):
            for fp in results:
                key = fp.packer_name
                if key not in merged:
                    # ilk goruste kopyala (layers_matched=1 ile)
                    merged[key] = PackerFingerprint(
                        packer_name=fp.packer_name,
                        version=fp.version,
                        confidence=fp.confidence,
                        evidence=list(fp.evidence),
                        category=fp.category,
                        platform=fp.platform,
                        layers_matched=1,
                    )
                else:
                    existing = merged[key]
                    # version: ilk None olmayan tut
                    if existing.version is None and fp.version:
                        existing.version = fp.version
                    # kanit birlestir (dedup ederek)
                    for ev in fp.evidence:
                        if ev not in existing.evidence:
                            existing.evidence.append(ev)
                    # confidence: max + boost
                    existing.confidence = max(existing.confidence, fp.confidence)
                    existing.layers_matched += 1
                    # category/platform: daha spesifik olani tut (bos/any degil)
                    if existing.platform == "any" and fp.platform != "any":
                        existing.platform = fp.platform

        # Multi-layer boost
        for fp in merged.values():
            if fp.layers_matched > 1:
                extra = (fp.layers_matched - 1) * self.MULTI_LAYER_BOOST
                fp.confidence = min(self.MAX_CONFIDENCE, fp.confidence + extra)

        result = list(merged.values())
        result.sort(key=lambda f: (-f.confidence, f.packer_name))
        return result


# ---------------------------------------------------------------------------
# Public helper
# ---------------------------------------------------------------------------

def fingerprint_packer(binary_path: Path | str) -> list[PackerFingerprint]:
    """Tek-cagrilik kestirme yardimcisi.

    Args:
        binary_path: Analiz edilecek dosya yolu.

    Returns:
        list[PackerFingerprint]: Confidence azalan sirada bulgular.
    """
    detector = PackerFingerprintDetector(binary_path)
    return detector.detect()


# ---------------------------------------------------------------------------
# Karadul entegrasyon notu (sadece yorum)
# ---------------------------------------------------------------------------
#
# `karadul/analyzers/packed_binary.py` icindeki `PackingDetector.detect()`
# su anda entropy + section ratio + birkac magic byte (UPX!, MEI, Nuitka)
# kullaniyor. Onerilen entegrasyon plani (Wave 3):
#
#   1. PackingDetector.detect() icinde, entropy analizinden ONCE
#      PackerFingerprintDetector calistir.
#   2. Yuksek confidence (>=0.85) bir fingerprint varsa:
#         packing_type = PackingType.<spesifik>  (ya da PackingType.UNKNOWN_PACKED
#                                                 + metadata['packer_name'])
#         confidence  = fingerprint.confidence
#         evidence   += fingerprint.evidence
#      Entropy analizini yine de yap (cross-check), ama "primary" sonuc
#      fingerprint'tir.
#   3. Fingerprint yoksa MEVCUT entropy fallback path calismaya devam.
#   4. Report bolumu:
#         "Detected Packer: UPX 3.96 (confidence 0.95, layers=2)"
#         "Detected Packer: VMProtect (confidence 0.92, layers=1)"
#   5. PackingType enum'una su anda olmayan packer isimleri (THEMIDA,
#      VMPROTECT, ENIGMA vb.) eklenir VEYA daha esnek olarak:
#         packing_type = PackingType.GENERIC_PACKED
#         metadata['fingerprints'] = [fp.to_dict() for fp in fingerprints]
#      sema degisikligi minimal kalir.
#
# Wave 3 PR'inde packed_binary.py'ye dokunulacak; bu modul saf eklenti.
