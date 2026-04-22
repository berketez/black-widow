"""Tests for karadul.analyzers.cpp_rtti -- Itanium multi/virtual inheritance.

Coverage (v1.10.0 Batch 3E):
- parse_itanium_si_bytes: __si_class_type_info
- parse_itanium_vmi_bytes: __vmi_class_type_info
  - multiple inheritance (2 base, non-virtual)
  - virtual inheritance (1 base, virtual flag)
  - diamond pattern (3 base, diamond_shaped flag + 2 virtual)
- ItaniumBaseInfo / ItaniumClassTypeInfo dataclass defaults
- RTTIParser._parse_base_classes integration (mock binary)
- parse_itanium end-to-end with multi-inheritance typeinfo
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.analyzers.cpp_rtti import (
    ItaniumBaseInfo,
    ItaniumClassTypeInfo,
    RTTIParser,
    parse_itanium_si_bytes,
    parse_itanium_vmi_bytes,
)


def _make_vmi_blob(
    flags: int, base_count: int, bases: list[tuple[int, int]],
    pointer_size: int = 8,
) -> bytes:
    """__vmi_class_type_info blob olustur.

    Layout:
      vtable_ptr (ptr) + name_ptr (ptr) + flags (u32) + base_count (u32)
      + [base_type_ptr (ptr), offset_flags (ptr, signed)] * base_count
    """
    blob = b"\x00" * pointer_size                                  # vtable_ptr
    blob += b"\x11" * pointer_size                                  # name_ptr
    blob += flags.to_bytes(4, "little", signed=False)
    blob += base_count.to_bytes(4, "little", signed=False)
    for base_ptr, offset_flags in bases:
        blob += base_ptr.to_bytes(pointer_size, "little", signed=False)
        blob += offset_flags.to_bytes(pointer_size, "little", signed=True)
    return blob


def _make_si_blob(base_ptr: int, pointer_size: int = 8) -> bytes:
    """__si_class_type_info blob: vtable + name_ptr + base_ptr."""
    return (
        b"\x00" * pointer_size
        + b"\x11" * pointer_size
        + base_ptr.to_bytes(pointer_size, "little", signed=False)
    )


# ===========================================================================
# Dataclass testleri
# ===========================================================================

def test_itanium_base_info_defaults():
    bi = ItaniumBaseInfo(
        base_typeinfo_name="Parent",
        offset=0,
        is_virtual=False,
        is_public=True,
    )
    assert bi.base_typeinfo_name == "Parent"
    assert bi.offset == 0


def test_itanium_class_type_info_defaults():
    info = ItaniumClassTypeInfo(kind="single", class_name="Child")
    assert info.flags == 0
    assert info.bases == []


# ===========================================================================
# parse_itanium_si_bytes
# ===========================================================================

def test_parse_si_bytes_basic():
    """__si_class_type_info: tek base, non-virtual, public, offset=0."""
    symbols_by_addr = {0xAAAA: "_ZTI6Parent"}
    blob = _make_si_blob(0xAAAA)
    info = parse_itanium_si_bytes(blob, symbols_by_addr)
    assert info is not None
    assert info.kind == "single"
    assert len(info.bases) == 1
    base = info.bases[0]
    assert base.base_typeinfo_name == "6Parent"  # raw mangled, no demangling
    assert base.offset == 0
    assert base.is_virtual is False
    assert base.is_public is True


def test_parse_si_bytes_missing_symbol():
    """Base typeinfo adresi sembolde yok -> sub_<addr> placeholder."""
    blob = _make_si_blob(0xDEAD)
    info = parse_itanium_si_bytes(blob, {})
    assert info is not None
    assert info.bases[0].base_typeinfo_name.startswith("sub_")


def test_parse_si_bytes_null_base():
    """base_ptr = 0 -> None (invalid)."""
    blob = _make_si_blob(0)
    assert parse_itanium_si_bytes(blob, {}) is None


def test_parse_si_bytes_too_short():
    """Yetersiz bytes -> None."""
    assert parse_itanium_si_bytes(b"\x00" * 8, {}) is None


# ===========================================================================
# parse_itanium_vmi_bytes
# ===========================================================================

def test_parse_vmi_multiple_inheritance():
    """Iki base, non-virtual (class D : B, C)."""
    bases = [
        (0xAAAA, 0x0 << 8 | 0x2),     # offset=0, public
        (0xBBBB, 0x10 << 8 | 0x2),    # offset=16, public
    ]
    blob = _make_vmi_blob(flags=0x0, base_count=2, bases=bases)
    symbols = {0xAAAA: "_ZTI1B", 0xBBBB: "_ZTI1C"}
    info = parse_itanium_vmi_bytes(blob, symbols)
    assert info is not None
    assert info.kind == "vmi"
    assert info.flags == 0x0
    assert len(info.bases) == 2
    b = info.bases[0]
    assert b.base_typeinfo_name == "1B"
    assert b.offset == 0
    assert b.is_virtual is False
    assert b.is_public is True
    c = info.bases[1]
    assert c.base_typeinfo_name == "1C"
    assert c.offset == 16


def test_parse_vmi_virtual_inheritance():
    """Tek base, virtual (class D : virtual B)."""
    bases = [
        # offset=8, virtual=1, public=2, combined flags = 3
        (0xAAAA, 0x8 << 8 | 0x1 | 0x2),
    ]
    blob = _make_vmi_blob(flags=0x0, base_count=1, bases=bases)
    info = parse_itanium_vmi_bytes(blob, {0xAAAA: "_ZTI1B"})
    assert info is not None
    b = info.bases[0]
    assert b.is_virtual is True
    assert b.is_public is True
    assert b.offset == 8


def test_parse_vmi_diamond_inheritance():
    """Diamond: class D : B, C where B, C : virtual A.

    VMI of D:
      flags = diamond_shaped_mask (0x2)
      bases = [B @ offset 0, C @ offset 16]  (non-virtual kendileri)
    """
    bases = [
        (0xAAAA, 0x0 << 8 | 0x2),
        (0xBBBB, 0x10 << 8 | 0x2),
    ]
    blob = _make_vmi_blob(flags=0x2, base_count=2, bases=bases)
    info = parse_itanium_vmi_bytes(blob, {0xAAAA: "_ZTI1B", 0xBBBB: "_ZTI1C"})
    assert info is not None
    assert info.flags == 0x2
    assert len(info.bases) == 2


def test_parse_vmi_rejects_absurd_base_count():
    """base_count > 64 veya 0 -> None (sanite)."""
    blob = _make_vmi_blob(flags=0, base_count=0, bases=[])
    assert parse_itanium_vmi_bytes(blob, {}) is None
    # base_count=100 > 64
    blob2 = _make_vmi_blob(flags=0, base_count=100, bases=[])
    assert parse_itanium_vmi_bytes(blob2, {}) is None


def test_parse_vmi_truncated():
    """Bilgisi eksik blob (base_count=3 ama 1 base veri) -> None."""
    # header diyor 3 base var ama blob'da sadece 1 var
    bases = [(0xAAAA, 0x2)]
    header = b"\x00" * 16 + (0).to_bytes(4, "little") + (3).to_bytes(4, "little")
    short_blob = header + (0xAAAA).to_bytes(8, "little") + (0x2).to_bytes(8, "little")
    assert parse_itanium_vmi_bytes(short_blob, {}) is None


def test_parse_vmi_negative_offset_virtual_base():
    """Virtual base icin negative offset_flags >> 8 signed."""
    # offset = -8, virtual=1, public=2 (signed)
    signed_offset_flags = ((-8) << 8) | 0x1 | 0x2
    # Python int; pack as signed 64-bit
    bases = [(0xAAAA, signed_offset_flags)]
    blob = _make_vmi_blob(flags=0x0, base_count=1, bases=bases)
    info = parse_itanium_vmi_bytes(blob, {0xAAAA: "_ZTI1B"})
    assert info is not None
    assert info.bases[0].offset == -8
    assert info.bases[0].is_virtual is True


# ===========================================================================
# RTTIParser._parse_base_classes integration
# ===========================================================================

def test_rtti_parser_parse_base_classes_vmi():
    """RTTIParser._parse_base_classes, mock binary ile vmi_class_type_info detect."""
    parser = RTTIParser()
    # Symbols: D'nin typeinfo vtable'i __vmi_class_type_info
    #          Base ptrlar B ve C typeinfo'larina isaret ediyor.
    # Mock binary: section_from_virtual_address() veri doner.
    symbols = {
        # Parent typeinfos are in symbols_by_addr parameter below
    }
    # va_to_sym icerigi: vmi_class_type_info vtable adresi + B/C typeinfo adresleri
    va_to_sym = {
        0x5000: "_ZTVN10__cxxabiv121__vmi_class_type_infoE",  # vmi vtable
        0xAAAA: "_ZTI1B",
        0xBBBB: "_ZTI1C",
    }
    # typeinfo'da vtable_ptr = 0x5010 (vmi vtable + 16, offset hesabi icin aday'lar -8, -16)
    vtable_ptr = 0x5010
    # VMI layout: 16 byte (2 ptr) + 4 (flags) + 4 (base_count) + 2 * 16 (base_info)
    base_info = (
        (0xAAAA).to_bytes(8, "little")
        + (0x0 << 8 | 0x2).to_bytes(8, "little", signed=True)
        + (0xBBBB).to_bytes(8, "little")
        + (0x10 << 8 | 0x2).to_bytes(8, "little", signed=True)
    )
    ti_blob = (
        vtable_ptr.to_bytes(8, "little")
        + (0x1234).to_bytes(8, "little")  # name_ptr
        + (0).to_bytes(4, "little")        # flags
        + (2).to_bytes(4, "little")        # base_count
        + base_info
    )
    section = MagicMock()
    section.virtual_address = 0x10000
    # Max blob size 2*8 + 8 + 64*16 = 1048 byte; pad icin kalan'i 0 ile doldur
    section.content = ti_blob + b"\x00" * (2048 - len(ti_blob))
    fake_binary = MagicMock()
    fake_binary.section_from_virtual_address.return_value = section

    infos = parser._parse_base_classes(
        fake_binary, typeinfo_addr=0x10000,
        symbols_by_addr=va_to_sym, pointer_size=8,
    )
    assert len(infos) == 2
    names = {bi.base_typeinfo_name for bi in infos}
    assert "1B" in names
    assert "1C" in names


def test_rtti_parser_parse_base_classes_si():
    """RTTIParser._parse_base_classes, __si_class_type_info detect."""
    parser = RTTIParser()
    va_to_sym = {
        0x6000: "_ZTVN10__cxxabiv120__si_class_type_infoE",
        0xAAAA: "_ZTI6Parent",
    }
    # vtable_ptr aday: 0x6010 (-16 yaptigimizda 0x6000)
    vtable_ptr = 0x6010
    ti_blob = (
        vtable_ptr.to_bytes(8, "little")
        + (0x1234).to_bytes(8, "little")
        + (0xAAAA).to_bytes(8, "little")
    )
    section = MagicMock()
    section.virtual_address = 0x20000
    section.content = ti_blob + b"\x00" * (512 - len(ti_blob))
    fake_binary = MagicMock()
    fake_binary.section_from_virtual_address.return_value = section

    infos = parser._parse_base_classes(
        fake_binary, typeinfo_addr=0x20000,
        symbols_by_addr=va_to_sym, pointer_size=8,
    )
    assert len(infos) == 1
    assert infos[0].base_typeinfo_name == "6Parent"
    assert infos[0].is_virtual is False
    assert infos[0].is_public is True


def test_rtti_parser_parse_base_classes_plain_has_no_bases():
    """Plain __class_type_info (non-derived) -> empty bases list."""
    parser = RTTIParser()
    va_to_sym = {
        0x7000: "_ZTVN10__cxxabiv117__class_type_infoE",
    }
    vtable_ptr = 0x7010
    ti_blob = (
        vtable_ptr.to_bytes(8, "little")
        + (0x1234).to_bytes(8, "little")
    )
    section = MagicMock()
    section.virtual_address = 0x30000
    section.content = ti_blob + b"\x00" * 128
    fake_binary = MagicMock()
    fake_binary.section_from_virtual_address.return_value = section

    infos = parser._parse_base_classes(
        fake_binary, typeinfo_addr=0x30000,
        symbols_by_addr=va_to_sym, pointer_size=8,
    )
    assert infos == []


# ===========================================================================
# parse_itanium end-to-end with multi-inheritance
# ===========================================================================

def test_parse_itanium_end_to_end_multi_inheritance(tmp_path: Path):
    """parse_itanium() + multi-inheritance typeinfo + vtable entegre."""
    parser = RTTIParser()
    binary_path = tmp_path / "fake.so"
    binary_path.write_bytes(b"placeholder")

    # Symbols (adresler belirlenecek)
    B_TI = 0x100
    C_TI = 0x200
    D_TI = 0x300
    D_VT = 0x400
    D_METHOD = 0x500
    VMI_VT = 0x600    # __vmi_class_type_info vtable
    symbols = {
        "_ZTI1B": B_TI,
        "_ZTI1C": C_TI,
        "_ZTI1D": D_TI,
        "_ZTV1D": D_VT,
        "_ZN1D3fooEv": D_METHOD,
        "_ZTVN10__cxxabiv121__vmi_class_type_infoE": VMI_VT,
    }

    # D'nin typeinfo blob'u (__vmi_class_type_info):
    #   vtable_ptr = VMI_VT + 16 (aday'lar: VMI_VT, VMI_VT-8, VMI_VT+16)
    # _parse_base_classes VMI_VT + 16'dan geriye doner: VMI_VT, VMI_VT-8
    # VMI_VT kendisi symbol -> match "vmi_class_type_info"
    d_ti_blob = (
        (VMI_VT + 16).to_bytes(8, "little")
        + (0x777).to_bytes(8, "little")
        + (0).to_bytes(4, "little")
        + (2).to_bytes(4, "little")
        + (B_TI).to_bytes(8, "little")
        + (0x0 << 8 | 0x2).to_bytes(8, "little", signed=True)
        + (C_TI).to_bytes(8, "little")
        + (0x10 << 8 | 0x2).to_bytes(8, "little", signed=True)
    )
    # D'nin vtable blob'u
    d_vt_blob = (
        (0).to_bytes(8, "little")         # offset-to-top
        + (D_TI).to_bytes(8, "little")     # typeinfo ptr
        + (D_METHOD).to_bytes(8, "little") # &foo
        + (0).to_bytes(8, "little")        # NULL terminator
    )

    def section_from_va(addr: int):
        if addr == D_TI:
            sec = MagicMock()
            sec.virtual_address = D_TI
            sec.content = d_ti_blob + b"\x00" * 128
            return sec
        if addr == D_VT:
            sec = MagicMock()
            sec.virtual_address = D_VT
            sec.content = d_vt_blob + b"\x00" * 64
            return sec
        # B ve C'nin typeinfo'lari: ayristirilmayacak (class_type_info),
        # sadece base_classes'a eklenecekler.
        if addr in (B_TI, C_TI):
            sec = MagicMock()
            sec.virtual_address = addr
            # Simple __class_type_info (plain): vtable_ptr (not matching VMI/SI)
            sec.content = (
                (0xABCDEF).to_bytes(8, "little")
                + (0x111).to_bytes(8, "little")
                + b"\x00" * 64
            )
            return sec
        return None

    binary = MagicMock()
    binary.section_from_virtual_address.side_effect = section_from_va

    hierarchy = parser.parse_itanium(binary_path, symbols=symbols, binary=binary)
    # 3 class: B, C, D
    names = {cls.name for cls in hierarchy.classes}
    assert "D" in names
    assert "B" in names
    assert "C" in names
    # D sinifinin base_classes listesi
    d_cls = next(c for c in hierarchy.classes if c.name == "D")
    assert "B" in d_cls.base_classes
    assert "C" in d_cls.base_classes
    # bases zenginlestirilmis bilgi
    base_map = {b["name"]: b for b in d_cls.bases}
    assert base_map["B"]["offset"] == 0
    assert base_map["C"]["offset"] == 16
    assert base_map["B"]["is_virtual"] is False
    assert base_map["B"]["is_public"] is True
    # D'nin metodu
    assert any("foo" in m["name"] for m in d_cls.methods)
