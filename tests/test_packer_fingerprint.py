"""karadul.analyzers.packer_fingerprint testleri.

Karadul v1.13 Dalga 1 Wave 2 — packer fingerprint detection.

Test stratejisi:
- Mock PE/ELF/Mach-O binary'leri minimal header + section table ile uretilir.
- `PackerFingerprintDetector(_data=...)` ile dosya IO baypas edilir.
- Beklentiler: dogru packer adi, beklenen confidence araligi, kategori/platform.
"""

from __future__ import annotations

import struct

import pytest

from karadul.analyzers.packer_fingerprint import (
    PackerFingerprint,
    PackerFingerprintDetector,
    fingerprint_packer,
    _detect_platform,
    _extract_pe_sections,
    _extract_elf_sections,
)


# ---------------------------------------------------------------------------
# Mock binary uretici
# ---------------------------------------------------------------------------

def _make_pe_with_sections(section_names: list[str], extra_data: bytes = b"") -> bytes:
    """Minimal valid PE dosyasi: DOS stub + PE header + N section table girdisi.

    Sadece section tablosunu okutmaya yetecek kadar dogru. Section veri icerigi
    yok (raw_offset/size = 0). Bizim parser sadece adlari okuyor.
    """
    # DOS header: MZ + 58 byte filler + e_lfanew @ 0x3C
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)  # e_lfanew = 0x80
    dos = dos.ljust(0x80, b"\x00")

    # PE signature
    pe_sig = b"PE\x00\x00"

    # COFF header (20 byte): Machine(2) NumSec(2) TimeStamp(4) PtrSym(4) NumSym(4) SizeOpt(2) Char(2)
    num_sec = len(section_names)
    size_opt = 0xE0  # standart PE32 optional header size
    coff = struct.pack(
        "<HHIIIHH",
        0x14c,        # Machine: i386
        num_sec,      # NumberOfSections
        0,            # TimeDateStamp
        0,            # PointerToSymbolTable
        0,            # NumberOfSymbols
        size_opt,     # SizeOfOptionalHeader
        0x102,        # Characteristics
    )

    # Optional header (placeholder, parser kullanmiyor)
    opt = b"\x00" * size_opt

    # Section table: her section 40 byte
    sections_blob = b""
    for name in section_names:
        name_b = name.encode("utf-8", errors="replace")[:8]
        name_b = name_b.ljust(8, b"\x00")
        # Name(8) VSize(4) VAddr(4) RawSize(4) RawPtr(4) RelocPtr(4) LinePtr(4)
        # NumReloc(2) NumLine(2) Char(4)
        sec = name_b + struct.pack("<IIIIIIHHI", 0, 0, 0, 0, 0, 0, 0, 0, 0)
        assert len(sec) == 40, f"section header boyutu yanlis: {len(sec)}"
        sections_blob += sec

    return dos + pe_sig + coff + opt + sections_blob + extra_data


def _make_elf64_with_sections(section_names: list[str]) -> bytes:
    """Minimal ELF64 dosyasi (LE) section tablosu ile."""
    # E_IDENT: \x7fELF, class=2, data=1, version=1, OSABI=0, ABIVer=0, pad
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    # Elf64_Ehdr: e_type(2) e_machine(2) e_version(4) e_entry(8) e_phoff(8)
    #             e_shoff(8) e_flags(4) e_ehsize(2) e_phentsize(2) e_phnum(2)
    #             e_shentsize(2) e_shnum(2) e_shstrndx(2)
    # = 64 byte total

    # shstrtab string'i: [0] null, sonra her section adi + null
    # ilk olarak shstrtab section'i da listeye ekleyelim ki kendi adini gormesi normal
    all_names = section_names + [".shstrtab"]
    shstrtab_buf = b"\x00"
    name_offsets: dict[str, int] = {}
    for name in all_names:
        name_offsets[name] = len(shstrtab_buf)
        shstrtab_buf += name.encode("utf-8") + b"\x00"

    # Layout: [Ehdr (64)] [shstrtab data (M)] [Section headers (N+1)*64]
    ehdr_size = 64
    shstr_offset = ehdr_size
    shstr_size = len(shstrtab_buf)
    shoff = shstr_offset + shstr_size
    shentsize = 64
    shnum = len(all_names)
    shstrndx = len(section_names)  # son section .shstrtab

    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,            # e_type ET_EXEC
        0x3e,         # e_machine x86_64
        1,            # e_version
        0,            # e_entry
        0,            # e_phoff
        shoff,        # e_shoff
        0,            # e_flags
        ehdr_size,    # e_ehsize
        0,            # e_phentsize
        0,            # e_phnum
        shentsize,    # e_shentsize
        shnum,        # e_shnum
        shstrndx,     # e_shstrndx
    )
    assert len(ehdr) == 64

    # Section headers — Elf64_Shdr (64 byte):
    # sh_name(4) sh_type(4) sh_flags(8) sh_addr(8) sh_offset(8) sh_size(8)
    # sh_link(4) sh_info(4) sh_addralign(8) sh_entsize(8)
    sec_hdrs = b""
    for name in all_names:
        name_idx = name_offsets[name]
        is_strtab = (name == ".shstrtab")
        sec_hdrs += struct.pack(
            "<IIQQQQIIQQ",
            name_idx,
            3 if is_strtab else 1,        # sh_type: STRTAB / PROGBITS
            0,                             # sh_flags
            0,                             # sh_addr
            shstr_offset if is_strtab else 0,   # sh_offset
            shstr_size if is_strtab else 0,     # sh_size
            0, 0,                          # sh_link, sh_info
            1,                             # sh_addralign
            0,                             # sh_entsize
        )
    assert len(sec_hdrs) == 64 * shnum

    return ehdr + shstrtab_buf + sec_hdrs


def _make_macho64_with_segments(seg_names: list[str]) -> bytes:
    """Minimal Mach-O 64 LE: header + LC_SEGMENT_64 komutlari (sadece adlar)."""
    magic = b"\xcf\xfa\xed\xfe"  # MH_MAGIC_64 LE
    cputype = 0x01000007   # x86_64
    cpusubtype = 3
    filetype = 2           # MH_EXECUTE
    ncmds = len(seg_names)

    # her LC_SEGMENT_64: 72 byte (cmd(4) cmdsize(4) segname(16) vmaddr(8)
    # vmsize(8) fileoff(8) filesize(8) maxprot(4) initprot(4) nsects(4) flags(4))
    cmdsize = 72
    sizeofcmds = ncmds * cmdsize
    flags = 0
    reserved = 0

    # mach_header_64: magic(4) cputype(4) cpusubtype(4) filetype(4) ncmds(4)
    #                 sizeofcmds(4) flags(4) reserved(4)  = 32 byte
    header = magic + struct.pack(
        "<IIIIIII",
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    )
    assert len(header) == 32

    cmds = b""
    for name in seg_names:
        segname = name.encode("utf-8")[:16].ljust(16, b"\x00")
        cmds += struct.pack(
            "<II16sQQQQIIII",
            0x19,         # LC_SEGMENT_64
            cmdsize,
            segname,
            0, 0,         # vmaddr, vmsize
            0, 0,         # fileoff, filesize
            0, 0,         # maxprot, initprot
            0, 0,         # nsects, flags
        )

    return header + cmds


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

class TestPlatformDetection:
    def test_pe_detected(self):
        data = _make_pe_with_sections(["UPX0", "UPX1"])
        assert _detect_platform(data) == "pe"

    def test_elf_detected(self):
        data = _make_elf64_with_sections([".text"])
        assert _detect_platform(data) == "elf"

    def test_macho_detected(self):
        data = _make_macho64_with_segments(["__TEXT"])
        assert _detect_platform(data) == "macho"

    def test_unknown_for_random(self):
        assert _detect_platform(b"random garbage data not a binary") == "unknown"

    def test_empty_data(self):
        assert _detect_platform(b"") == "unknown"


# ---------------------------------------------------------------------------
# Section extraction
# ---------------------------------------------------------------------------

class TestSectionExtraction:
    def test_pe_sections_extracted(self):
        data = _make_pe_with_sections(["UPX0", "UPX1", ".rsrc"])
        sections = _extract_pe_sections(data)
        assert "UPX0" in sections
        assert "UPX1" in sections
        assert ".rsrc" in sections

    def test_pe_invalid_returns_empty(self):
        # MZ degil
        assert _extract_pe_sections(b"\x00" * 100) == []

    def test_elf_sections_extracted(self):
        data = _make_elf64_with_sections([".text", ".data"])
        sections = _extract_elf_sections(data)
        assert ".text" in sections
        assert ".data" in sections


# ---------------------------------------------------------------------------
# Section-based detection
# ---------------------------------------------------------------------------

class TestSectionDetection:
    def test_upx_pe(self):
        data = _make_pe_with_sections(["UPX0", "UPX1", ".rsrc"])
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_sections()
        names = [r.packer_name for r in results]
        assert "UPX" in names
        upx = next(r for r in results if r.packer_name == "UPX")
        assert upx.confidence >= 0.90
        assert upx.category == "compressor"
        assert upx.platform == "pe"

    def test_vmprotect_pe(self):
        data = _make_pe_with_sections([".vmp0", ".vmp1", ".text"])
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_sections()
        names = [r.packer_name for r in results]
        assert "VMProtect" in names
        vmp = next(r for r in results if r.packer_name == "VMProtect")
        assert vmp.confidence >= 0.90
        assert vmp.category == "vm-protector"

    def test_themida_pe(self):
        data = _make_pe_with_sections([".themida", ".text"])
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_sections()
        assert any(r.packer_name == "Themida" for r in results)

    def test_aspack_pe(self):
        data = _make_pe_with_sections([".aspack", ".adata", ".text"])
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_sections()
        aspack = [r for r in results if r.packer_name == "ASPack"]
        # require_all=True kuralı + sadece .aspack kuralı; en az biri eslesmeli
        assert aspack
        assert max(r.confidence for r in aspack) >= 0.85

    def test_mpress_pe(self):
        data = _make_pe_with_sections([".MPRESS1", ".MPRESS2"])
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_sections()
        assert any(r.packer_name == "MPRESS" for r in results)

    def test_clean_binary_no_packer(self):
        data = _make_pe_with_sections([".text", ".data", ".rdata", ".rsrc"])
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_sections()
        assert results == []

    def test_macho_upx(self):
        data = _make_macho64_with_segments(["__TEXT", "__XHDR", "__LINKEDIT"])
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_sections()
        assert any(r.packer_name == "UPX" and r.platform == "macho" for r in results)


# ---------------------------------------------------------------------------
# String-based detection
# ---------------------------------------------------------------------------

class TestStringDetection:
    def test_pyinstaller_meipass(self):
        # Temiz PE + _MEIPASS string'i payload'da
        data = _make_pe_with_sections([".text"]) + b"\x00\x00_MEIPASS\x00\x00"
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_strings()
        assert any(r.packer_name == "PyInstaller" for r in results)

    def test_nuitka(self):
        data = _make_pe_with_sections([".text"]) + b"hello __nuitka_ world"
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_strings()
        assert any(r.packer_name == "Nuitka" for r in results)

    def test_upx_banner_with_version(self):
        banner = b"UPX 3.96 Copyright (C) 1996-2020 the UPX Team"
        data = _make_pe_with_sections([".text"]) + banner
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_strings()
        upx_hits = [r for r in results if r.packer_name == "UPX"]
        assert upx_hits
        # version yakalandi mi?
        assert any(r.version == "3.96" for r in upx_hits)

    def test_vmprotect_string(self):
        data = _make_pe_with_sections([".text"]) + b"\x00VMProtect Ultimate\x00"
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_strings()
        assert any(r.packer_name == "VMProtect" for r in results)

    def test_confuserex(self):
        data = _make_pe_with_sections([".text"]) + b"\x00ConfuserEx v1.0.0\x00"
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_strings()
        assert any(r.packer_name == "Confuser" for r in results)

    def test_inno_setup_with_version(self):
        data = _make_pe_with_sections([".text"]) + b"Inno Setup Setup Data (6.2.1)"
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_strings()
        inno = [r for r in results if r.packer_name == "InnoSetup"]
        assert inno
        assert any(r.version == "6.2.1" for r in inno)

    def test_clean_binary_no_string_match(self):
        # icinde bilinen marker olmayan PE
        data = _make_pe_with_sections([".text"]) + b"hello world this is a normal binary"
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_strings()
        assert results == []


# ---------------------------------------------------------------------------
# Entry-pattern detection
# ---------------------------------------------------------------------------

class TestEntryPatternDetection:
    def test_aspack_stub(self):
        # ASPack stub: 60 E8 03 00 00 00 E9 EB
        stub = b"\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d"
        # PE header'in hemen sonrasina yerlestir (max_offset 0x4000 icinde olmali)
        data = _make_pe_with_sections([".text"]) + stub + b"\x00" * 100
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_entry_pattern()
        assert any(r.packer_name == "ASPack" for r in results)

    def test_telock_stub(self):
        stub = b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed"
        data = _make_pe_with_sections([".text"]) + stub + b"\x00" * 100
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_entry_pattern()
        assert any(r.packer_name == "tElock" for r in results)

    def test_no_pattern_clean(self):
        data = _make_pe_with_sections([".text"]) + b"\x00" * 4096
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect_by_entry_pattern()
        # bazi cok zayif (FSG = "\xbb") kurallar tetiklenebilir; ama kritik
        # olanlar (ASPack, tElock) tetiklenmemeli
        names = [r.packer_name for r in results]
        assert "ASPack" not in names
        assert "tElock" not in names


# ---------------------------------------------------------------------------
# Multi-layer detect() — boost ve aggregation
# ---------------------------------------------------------------------------

class TestMultiLayerDetection:
    def test_upx_section_plus_string_boost(self):
        # UPX0/UPX1 sections + UPX banner → 2 katman → boost +0.05
        banner = b"UPX 4.0.1 Copyright (C) 1996-2024 the UPX Team"
        data = _make_pe_with_sections(["UPX0", "UPX1", ".rsrc"]) + banner
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect()
        upx = [r for r in results if r.packer_name == "UPX"]
        assert upx, "UPX bulunmadi"
        u = upx[0]
        assert u.layers_matched >= 2
        # base 0.95 + 0.05 boost = 0.99 (cap'e takiliyor)
        assert u.confidence >= 0.95
        assert u.version == "4.0.1"
        # her iki katmandan kanit
        assert any("section adi" in e for e in u.evidence)
        assert any("string" in e for e in u.evidence)

    def test_nested_themida_plus_upx(self):
        # Themida + UPX birlikte (nested packer ornegi)
        data = _make_pe_with_sections(["UPX0", "UPX1", ".themida", ".rsrc"])
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect()
        names = [r.packer_name for r in results]
        assert "UPX" in names
        assert "Themida" in names

    def test_clean_binary_no_findings(self):
        data = _make_pe_with_sections([".text", ".data", ".rdata", ".rsrc"])
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect()
        assert results == []

    def test_results_sorted_by_confidence(self):
        # iki packer: biri yuksek (UPX 0.95+boost) digeri orta (Petite 0.88)
        data = (
            _make_pe_with_sections(["UPX0", "UPX1", ".petite", ".text"])
            + b"UPX 3.96 Copyright "
        )
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect()
        confs = [r.confidence for r in results]
        # azalan sirada
        assert confs == sorted(confs, reverse=True)


# ---------------------------------------------------------------------------
# fingerprint_packer helper + dosya IO yolu
# ---------------------------------------------------------------------------

class TestFingerprintPackerHelper:
    def test_helper_with_real_file(self, tmp_path):
        binpath = tmp_path / "fake_upx.exe"
        data = _make_pe_with_sections(["UPX0", "UPX1", ".rsrc"])
        binpath.write_bytes(data)

        results = fingerprint_packer(binpath)
        assert any(r.packer_name == "UPX" for r in results)

    def test_helper_missing_file(self, tmp_path):
        ghost = tmp_path / "does_not_exist.bin"
        results = fingerprint_packer(ghost)
        assert results == []

    def test_to_dict_serializable(self):
        fp = PackerFingerprint(
            packer_name="UPX",
            version="3.96",
            confidence=0.95,
            evidence=["section adi: UPX0"],
            category="compressor",
            platform="pe",
            layers_matched=1,
        )
        d = fp.to_dict()
        assert d["packer_name"] == "UPX"
        assert d["version"] == "3.96"
        assert d["confidence"] == 0.95
        assert d["layers_matched"] == 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_data(self):
        det = PackerFingerprintDetector("dummy", _data=b"")
        assert det.detect() == []
        assert det.detect_by_sections() == []
        assert det.detect_by_strings() == []
        assert det.detect_by_entry_pattern() == []

    def test_truncated_pe_no_crash(self):
        # MZ + e_lfanew hemen sonra dosya bitiyor — parser crash etmemeli
        truncated = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 0x10
        det = PackerFingerprintDetector("dummy", _data=truncated)
        # crash'lemez, bos liste doner
        results = det.detect()
        # bilinen string yok, section parse fail → en fazla zayif entry pattern
        # (FSG = \xbb) tetiklenebilir; yine de crash yok
        assert isinstance(results, list)

    def test_multi_layer_evidence_no_duplication(self):
        # Ayni evidence iki katmanda gozukse de tek tutulmali
        data = _make_pe_with_sections(["UPX0", "UPX1"]) + b"UPX 3.96 Copyright "
        det = PackerFingerprintDetector("dummy", _data=data)
        results = det.detect()
        upx = next(r for r in results if r.packer_name == "UPX")
        # dedup: ayni evidence string'i iki kez gecmemeli
        assert len(upx.evidence) == len(set(upx.evidence))
