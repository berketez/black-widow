"""Tests for karadul.analyzers.cpp_rtti -- MSVC (Windows C++) RTTI parser.

Coverage (v1.10.0 Batch 3E):
- demangle_msvc: basic class, struct, nested namespace, template (primitive),
  template (class), unknown fallback
- MSVCTypeDescriptor / MSVCBaseClassDescriptor / MSVCClassHierarchyDescriptor
  / MSVCCompleteObjectLocator dataclass defaults
- MSVCRTTIParser.scan_type_descriptors: .?AV / .?AU scanning
- MSVCRTTIParser.scan_complete_object_locators: x64 (sig=1) + x86 (sig=0)
- MSVCRTTIParser.parse_class_hierarchy_descriptor: BCD / CHD walk
- MSVCRTTIParser.parse_msvc: end-to-end synthetic PE-like blob
- CppRttiAnalyzer.analyze: PE format detection -> MSVC path

Fixture: Sentetik `.rdata` section layout'u. Gercek PE parse etmiyoruz;
MagicMock lief.Binary objesi + ayarlanmis sections listesi kullaniyoruz.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from karadul.analyzers.cpp_rtti import (
    CppRttiAnalyzer,
    CppRttiResult,
    MSVCBaseClassDescriptor,
    MSVCClassHierarchyDescriptor,
    MSVCCompleteObjectLocator,
    MSVCRTTIParser,
    MSVCTypeDescriptor,
    demangle_msvc,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_rdata_section(va: int, content: bytes) -> MagicMock:
    section = MagicMock()
    section.name = ".rdata"
    section.virtual_address = va
    section.content = content
    return section


def _make_binary_with_rdata(
    rdata_va: int, rdata_content: bytes, image_base: int = 0x140000000,
) -> MagicMock:
    """Mock lief.Binary with a single .rdata section."""
    binary = MagicMock()
    rdata = _make_rdata_section(rdata_va, rdata_content)
    binary.sections = [rdata]

    def section_from_va(addr: int):
        if rdata_va <= addr < rdata_va + len(rdata_content):
            return rdata
        return None

    binary.section_from_virtual_address.side_effect = section_from_va
    binary.imagebase = image_base
    return binary


def _td_blob(
    vftable_ptr: int, spare: int, name_bytes: bytes, pointer_size: int = 8,
) -> bytes:
    """TypeDescriptor layout: vftable_ptr + spare + null-terminated name."""
    return (
        vftable_ptr.to_bytes(pointer_size, "little")
        + spare.to_bytes(pointer_size, "little")
        + name_bytes + b"\x00"
    )


def _col_blob_x64(
    signature: int, offset: int, cd_offset: int,
    td_rva: int, chd_rva: int, object_base: int,
) -> bytes:
    return (
        signature.to_bytes(4, "little")
        + offset.to_bytes(4, "little")
        + cd_offset.to_bytes(4, "little")
        + td_rva.to_bytes(4, "little")
        + chd_rva.to_bytes(4, "little")
        + object_base.to_bytes(4, "little")
    )


def _chd_blob(
    signature: int, attrs: int, num_bases: int, bca_rva: int,
) -> bytes:
    return (
        signature.to_bytes(4, "little")
        + attrs.to_bytes(4, "little")
        + num_bases.to_bytes(4, "little")
        + bca_rva.to_bytes(4, "little")
    )


def _bcd_blob(
    td_rva: int, num_contained: int,
    mdisp: int, pdisp: int, vdisp: int,
    attrs: int, chd_rva: int = 0,
) -> bytes:
    return (
        td_rva.to_bytes(4, "little")
        + num_contained.to_bytes(4, "little")
        + mdisp.to_bytes(4, "little", signed=True)
        + pdisp.to_bytes(4, "little", signed=True)
        + vdisp.to_bytes(4, "little", signed=True)
        + attrs.to_bytes(4, "little")
        + chd_rva.to_bytes(4, "little")
    )


# ===========================================================================
# demangle_msvc testleri
# ===========================================================================

def test_demangle_msvc_basic_class():
    """.?AVMyClass@@ -> class MyClass"""
    assert demangle_msvc(".?AVMyClass@@") == "class MyClass"


def test_demangle_msvc_basic_struct():
    """.?AUMyStruct@@ -> struct MyStruct"""
    assert demangle_msvc(".?AUMyStruct@@") == "struct MyStruct"


def test_demangle_msvc_nested_namespace():
    """.?AVNested@Outer@@ -> class Outer::Nested"""
    assert demangle_msvc(".?AVNested@Outer@@") == "class Outer::Nested"


def test_demangle_msvc_deep_namespace():
    """.?AVA@B@C@@ -> class C::B::A"""
    assert demangle_msvc(".?AVA@B@C@@") == "class C::B::A"


def test_demangle_msvc_template_primitive():
    """.?AV?$Vec@H@@ -> class Vec<int>"""
    assert demangle_msvc(".?AV?$Vec@H@@") == "class Vec<int>"


def test_demangle_msvc_template_class_arg():
    """.?AV?$Vector@VMyClass@@@@ -> class Vector<class MyClass>"""
    result = demangle_msvc(".?AV?$Vector@VMyClass@@@@")
    assert result == "class Vector<class MyClass>"


def test_demangle_msvc_template_with_namespace():
    """.?AV?$Tpl@H@NS@@ -> class NS::Tpl<int>"""
    result = demangle_msvc(".?AV?$Tpl@H@NS@@")
    assert result == "class NS::Tpl<int>"


def test_demangle_msvc_empty_string():
    assert demangle_msvc("") == ""


def test_demangle_msvc_unknown_format_passthrough():
    """Bilinmeyen format input oldugu gibi doner."""
    assert demangle_msvc("not_msvc_mangling") == "not_msvc_mangling"


def test_demangle_msvc_bytes_input():
    """Bytes input destekli."""
    assert demangle_msvc(b".?AVFoo@@") == "class Foo"


# ===========================================================================
# Dataclass testleri
# ===========================================================================

def test_msvc_type_descriptor_defaults():
    td = MSVCTypeDescriptor(
        addr=0x1000, vftable_ptr=0, spare=0, name=".?AVA@@",
    )
    assert td.demangled == ""
    assert td.name == ".?AVA@@"


def test_msvc_bcd_attributes_virtual():
    bcd = MSVCBaseClassDescriptor(
        addr=0, type_descriptor=0, num_contained_bases=0,
        pmd_mdisp=0, pmd_pdisp=-1, pmd_vdisp=0,
        attributes=0x10,  # BCD_VIRTUAL
    )
    assert bcd.is_virtual is True
    assert bcd.is_public is True


def test_msvc_bcd_attributes_private():
    bcd = MSVCBaseClassDescriptor(
        addr=0, type_descriptor=0, num_contained_bases=0,
        pmd_mdisp=0, pmd_pdisp=-1, pmd_vdisp=0,
        attributes=0x04,  # BCD_PRIVATE
    )
    assert bcd.is_public is False


def test_msvc_chd_inheritance_flags():
    chd = MSVCClassHierarchyDescriptor(
        addr=0, signature=0, attributes=0x03,  # MULTI | VIRTUAL
        num_base_classes=3, base_class_array=0,
    )
    assert chd.has_multiple_inheritance is True
    assert chd.has_virtual_inheritance is True


def test_msvc_col_defaults():
    col = MSVCCompleteObjectLocator(
        addr=0x1000, signature=1, offset=0, cd_offset=0,
        type_descriptor=0x2000, class_hierarchy=0x3000,
    )
    assert col.type_desc_obj is None
    assert col.chd_obj is None
    assert col.object_base == 0


# ===========================================================================
# scan_type_descriptors
# ===========================================================================

def test_scan_type_descriptors_basic_class():
    """.?AVMyClass@@ scan eder ve TypeDescriptor insa eder."""
    pointer_size = 8
    image_base = 0x140000000
    rdata_va = 0x140010000
    # TD layout: vftable_ptr (8) + spare (8) + ".?AVMyClass@@\0"
    name = b".?AVMyClass@@"
    content = _td_blob(
        vftable_ptr=0xDEADBEEF, spare=0, name_bytes=name,
        pointer_size=pointer_size,
    )
    binary = _make_binary_with_rdata(rdata_va, content, image_base)
    parser = MSVCRTTIParser()
    tds = parser.scan_type_descriptors(binary, image_base, pointer_size)
    assert len(tds) == 1
    td = next(iter(tds.values()))
    assert td.name == ".?AVMyClass@@"
    assert td.demangled == "class MyClass"
    assert td.vftable_ptr == 0xDEADBEEF
    # td.addr = name_va - 2*ptr (name rdata basinda +16 offset)
    name_va = rdata_va + content.find(name)
    assert td.addr == name_va - 2 * pointer_size


def test_scan_type_descriptors_multiple():
    """Iki farkli .?AV... stringi -> iki TypeDescriptor."""
    pointer_size = 8
    image_base = 0x140000000
    rdata_va = 0x140010000
    name1 = b".?AVFoo@@"
    name2 = b".?AUBar@@"
    content = (
        _td_blob(0, 0, name1, pointer_size)
        + _td_blob(0, 0, name2, pointer_size)
    )
    binary = _make_binary_with_rdata(rdata_va, content, image_base)
    parser = MSVCRTTIParser()
    tds = parser.scan_type_descriptors(binary, image_base, pointer_size)
    assert len(tds) == 2
    names = {td.name for td in tds.values()}
    assert ".?AVFoo@@" in names
    assert ".?AUBar@@" in names


def test_scan_type_descriptors_no_rdata():
    """.rdata yoksa empty dict."""
    binary = MagicMock()
    binary.sections = []
    parser = MSVCRTTIParser()
    assert parser.scan_type_descriptors(binary, 0, 8) == {}


# ===========================================================================
# scan_complete_object_locators
# ===========================================================================

def test_scan_col_x64():
    """x64 COL (signature=1) tespit edilir."""
    pointer_size = 8
    image_base = 0x140000000
    rdata_va = 0x140010000
    name = b".?AVMyClass@@"
    # Layout:
    #   [0..0x20]  TypeDescriptor (16 hdr + name + null)
    #   [padding aligned to 4]
    #   COL
    td_blob = _td_blob(0, 0, name, pointer_size)
    # pad to 4-byte alignment
    pad = (4 - len(td_blob) % 4) % 4
    col_offset_in_rdata = len(td_blob) + pad
    name_va = rdata_va + td_blob.find(name)
    td_va = name_va - 2 * pointer_size
    td_rva = td_va - image_base
    # Dummy CHD/BCA RVA (gerekli degil, sadece COL sig eslesmesi icin)
    chd_rva = 0xAAAA
    col_blob = _col_blob_x64(
        signature=1, offset=0, cd_offset=0,
        td_rva=td_rva, chd_rva=chd_rva, object_base=0,
    )
    content = td_blob + b"\x00" * pad + col_blob
    binary = _make_binary_with_rdata(rdata_va, content, image_base)
    parser = MSVCRTTIParser()
    tds = parser.scan_type_descriptors(binary, image_base, pointer_size)
    cols = parser.scan_complete_object_locators(
        binary, tds, image_base, pointer_size,
    )
    assert len(cols) == 1
    col = cols[0]
    assert col.signature == 1
    assert col.type_descriptor == td_va
    assert col.vftable_addr == col.addr + pointer_size


def test_scan_col_x86():
    """x86 COL (signature=0, absolute VAs) tespit edilir."""
    pointer_size = 4
    image_base = 0x400000
    rdata_va = 0x401000
    name = b".?AVA@@"
    td_blob = _td_blob(0, 0, name, pointer_size)
    pad = (4 - len(td_blob) % 4) % 4
    name_va = rdata_va + td_blob.find(name)
    td_va = name_va - 2 * pointer_size
    chd_va = 0xBEEF
    # x86 COL = 20 byte (no object_base)
    col_blob = (
        (0).to_bytes(4, "little")  # signature
        + (0).to_bytes(4, "little")  # offset
        + (0).to_bytes(4, "little")  # cd_offset
        + td_va.to_bytes(4, "little")
        + chd_va.to_bytes(4, "little")
    )
    content = td_blob + b"\x00" * pad + col_blob
    binary = _make_binary_with_rdata(rdata_va, content, image_base)
    parser = MSVCRTTIParser()
    tds = parser.scan_type_descriptors(binary, image_base, pointer_size)
    cols = parser.scan_complete_object_locators(
        binary, tds, image_base, pointer_size,
    )
    assert len(cols) == 1
    assert cols[0].signature == 0
    assert cols[0].type_descriptor == td_va


def test_scan_col_rejects_invalid_offset():
    """Offset alani asiri yuksekse COL kabul edilmez (false-positive'i kirpma)."""
    pointer_size = 8
    image_base = 0x140000000
    rdata_va = 0x140010000
    name = b".?AVA@@"
    td_blob = _td_blob(0, 0, name, pointer_size)
    name_va = rdata_va + td_blob.find(name)
    td_va = name_va - 2 * pointer_size
    td_rva = td_va - image_base
    pad = (4 - len(td_blob) % 4) % 4
    # offset = 0xFFFFFFFF (sanite sinirini geciyor)
    col_blob = _col_blob_x64(1, 0xFFFFFFFF, 0, td_rva, 0xAAAA, 0)
    content = td_blob + b"\x00" * pad + col_blob
    binary = _make_binary_with_rdata(rdata_va, content, image_base)
    parser = MSVCRTTIParser()
    tds = parser.scan_type_descriptors(binary, image_base, pointer_size)
    cols = parser.scan_complete_object_locators(
        binary, tds, image_base, pointer_size,
    )
    assert len(cols) == 0


# ===========================================================================
# parse_class_hierarchy_descriptor
# ===========================================================================

def test_parse_chd_with_one_base():
    """CHD + BCA + BCD parse zinciri."""
    pointer_size = 8
    image_base = 0x140000000
    rdata_va = 0x140020000
    # TD #1: Child (.?AVChild@@)
    td_child = _td_blob(0, 0, b".?AVChild@@", pointer_size)
    # TD #2: Parent (.?AVParent@@)
    td_parent = _td_blob(0, 0, b".?AVParent@@", pointer_size)
    # Child TD va = rdata_va + offset + 16 - 16 = rdata_va + offset
    child_name_va = rdata_va + td_child.find(b".?AVChild@@")
    child_td_va = child_name_va - 2 * pointer_size
    parent_offset = len(td_child)
    parent_name_va = rdata_va + parent_offset + td_parent.find(b".?AVParent@@")
    parent_td_va = parent_name_va - 2 * pointer_size

    # BCD: Parent BCD (child's base)
    parent_td_rva = parent_td_va - image_base
    bcd_blob = _bcd_blob(
        td_rva=parent_td_rva, num_contained=0,
        mdisp=0, pdisp=-1, vdisp=0, attrs=0x40,  # HAS_HIERARCHY_DESCRIPTOR
        chd_rva=0,
    )
    bcd_offset = parent_offset + len(td_parent)
    bcd_va = rdata_va + bcd_offset
    # BCA: tek RVA pointer Parent BCD'ye
    bcd_rva = bcd_va - image_base
    bca_blob = bcd_rva.to_bytes(4, "little")
    bca_offset = bcd_offset + len(bcd_blob)
    bca_va = rdata_va + bca_offset
    # CHD
    chd_offset = bca_offset + len(bca_blob)
    chd_va = rdata_va + chd_offset
    bca_rva = bca_va - image_base
    chd_blob = _chd_blob(
        signature=0, attrs=0x0,  # non-multiple, non-virtual
        num_bases=1, bca_rva=bca_rva,
    )

    content = td_child + td_parent + bcd_blob + bca_blob + chd_blob
    binary = _make_binary_with_rdata(rdata_va, content, image_base)

    parser = MSVCRTTIParser()
    tds = parser.scan_type_descriptors(binary, image_base, pointer_size)
    chd = parser.parse_class_hierarchy_descriptor(
        binary, chd_va, image_base, pointer_size, type_descriptors=tds,
    )
    assert chd is not None
    assert chd.num_base_classes == 1
    assert len(chd.base_descriptors) == 1
    bcd = chd.base_descriptors[0]
    assert bcd.type_descriptor == parent_td_va
    assert bcd.type_name == "class Parent"
    assert bcd.is_virtual is False


def test_parse_chd_virtual_inheritance_flag():
    """CHD.attributes bit-0x02 => virtual inheritance."""
    pointer_size = 8
    image_base = 0x140000000
    rdata_va = 0x140030000
    # Tek bir BCD yeterli (virtual BCD flag da 0x10)
    bcd_blob = _bcd_blob(
        td_rva=0, num_contained=0, mdisp=0, pdisp=0, vdisp=8,
        attrs=0x10,  # BCD_VIRTUAL
        chd_rva=0,
    )
    bca_blob = (rdata_va - image_base).to_bytes(4, "little")
    chd_blob = _chd_blob(
        signature=0, attrs=0x03,  # MULTI|VIRTUAL
        num_bases=1, bca_rva=rdata_va + len(bcd_blob) - image_base,
    )
    content = bcd_blob + bca_blob + chd_blob
    binary = _make_binary_with_rdata(rdata_va, content, image_base)
    parser = MSVCRTTIParser()
    chd_va = rdata_va + len(bcd_blob) + len(bca_blob)
    chd = parser.parse_class_hierarchy_descriptor(
        binary, chd_va, image_base, pointer_size,
    )
    assert chd is not None
    assert chd.has_multiple_inheritance is True
    assert chd.has_virtual_inheritance is True


# ===========================================================================
# CppRttiAnalyzer
# ===========================================================================

def test_analyzer_detects_pe_format(tmp_path: Path):
    """MZ header -> PE detection."""
    pe_path = tmp_path / "dummy.exe"
    pe_path.write_bytes(b"MZ\x00\x00" + b"\x00" * 60)
    analyzer = CppRttiAnalyzer()
    fmt = analyzer._detect_format(pe_path)
    assert fmt == "pe"


def test_analyzer_detects_elf_format(tmp_path: Path):
    """ELF magic -> elf."""
    elf_path = tmp_path / "dummy.so"
    elf_path.write_bytes(b"\x7fELF" + b"\x00" * 32)
    analyzer = CppRttiAnalyzer()
    fmt = analyzer._detect_format(elf_path)
    assert fmt == "elf"


def test_analyzer_detects_unknown(tmp_path: Path):
    other_path = tmp_path / "foo.txt"
    other_path.write_bytes(b"random garbage not a binary")
    analyzer = CppRttiAnalyzer()
    fmt = analyzer._detect_format(other_path)
    assert fmt == "unknown"


def test_analyzer_unknown_format_returns_empty(tmp_path: Path):
    other_path = tmp_path / "foo.txt"
    other_path.write_bytes(b"nonsense")
    analyzer = CppRttiAnalyzer()
    result = analyzer.analyze(other_path)
    assert isinstance(result, CppRttiResult)
    assert result.abi == "unknown"
    assert result.hierarchy.classes == []


# ===========================================================================
# End-to-end MSVC parse_msvc (sentetik PE blob)
# ===========================================================================

def test_parse_msvc_end_to_end(tmp_path: Path):
    """Sentetik `.rdata` icerigi ile tam MSVC RTTI zinciri:
    TypeDescriptor + COL + CHD + BCD -> ClassHierarchy."""
    pointer_size = 8
    image_base = 0x140000000
    rdata_va = 0x140040000

    # 1) Child TypeDescriptor
    td_child_hdr_spare = _td_blob(0, 0, b".?AVChild@@", pointer_size)
    # 2) Parent TypeDescriptor (for self-BCD)
    td_parent = _td_blob(0, 0, b".?AVParent@@", pointer_size)

    child_name_offset = td_child_hdr_spare.find(b".?AVChild@@")
    child_name_va = rdata_va + child_name_offset
    child_td_va = child_name_va - 2 * pointer_size

    parent_name_offset = len(td_child_hdr_spare) + td_parent.find(b".?AVParent@@")
    parent_name_va = rdata_va + parent_name_offset
    parent_td_va = parent_name_va - 2 * pointer_size

    # 3) Child-self BCD
    child_self_bcd_offset = len(td_child_hdr_spare) + len(td_parent)
    child_self_bcd = _bcd_blob(
        td_rva=child_td_va - image_base,
        num_contained=1, mdisp=0, pdisp=-1, vdisp=0,
        attrs=0x40, chd_rva=0,
    )
    # 4) Parent BCD
    parent_bcd_offset = child_self_bcd_offset + len(child_self_bcd)
    parent_bcd = _bcd_blob(
        td_rva=parent_td_va - image_base,
        num_contained=0, mdisp=8, pdisp=-1, vdisp=0,
        attrs=0x40, chd_rva=0,
    )
    # 5) BCA: 2 entries (child self BCD RVA, parent BCD RVA)
    bca_offset = parent_bcd_offset + len(parent_bcd)
    bca_va = rdata_va + bca_offset
    child_self_bcd_va = rdata_va + child_self_bcd_offset
    parent_bcd_va = rdata_va + parent_bcd_offset
    bca_blob = (
        (child_self_bcd_va - image_base).to_bytes(4, "little")
        + (parent_bcd_va - image_base).to_bytes(4, "little")
    )
    # 6) CHD
    chd_offset = bca_offset + len(bca_blob)
    chd_va = rdata_va + chd_offset
    chd_blob = _chd_blob(
        signature=0, attrs=0x0,
        num_bases=2, bca_rva=bca_va - image_base,
    )
    # 7) COL (x64)
    col_offset = chd_offset + len(chd_blob)
    # pad to 4 byte aligned (already 4-aligned from prior blobs of 4/20 mul)
    pad = (4 - col_offset % 4) % 4
    col_offset += pad
    col_va = rdata_va + col_offset
    col_blob = _col_blob_x64(
        signature=1, offset=0, cd_offset=0,
        td_rva=child_td_va - image_base,
        chd_rva=chd_va - image_base,
        object_base=col_va - image_base,
    )
    content = (
        td_child_hdr_spare + td_parent
        + child_self_bcd + parent_bcd
        + bca_blob + chd_blob
        + b"\x00" * pad + col_blob
    )
    binary = _make_binary_with_rdata(rdata_va, content, image_base)

    parser = MSVCRTTIParser()
    fake_path = tmp_path / "dummy.exe"
    fake_path.write_bytes(b"MZ" + b"\x00" * 64)

    hierarchy, cols = parser.parse_msvc(
        fake_path, binary=binary, pointer_size=pointer_size,
    )
    assert len(hierarchy.classes) == 1
    cls = hierarchy.classes[0]
    assert cls.name == "class Child"
    assert cls.mangled_name == ".?AVChild@@"
    assert cls.typeinfo_addr == f"0x{child_td_va:x}"
    assert cls.vtable_addr == f"0x{col_va + pointer_size:x}"
    # Parent base listed (Child-self skip edildi: type_descriptor == td.addr)
    assert "class Parent" in cls.base_classes
    assert len(cls.bases) == 1
    base = cls.bases[0]
    assert base["name"] == "class Parent"
    assert base["offset"] == 8
    assert base["is_virtual"] is False
    assert base["is_public"] is True
    assert len(cols) == 1


# ---------------------------------------------------------------------------
# v1.10.0 Batch 6A regression — Codex RTTI audit
# ---------------------------------------------------------------------------

def test_col_pself_alias_matches_object_base():
    """Batch 6A: ``pSelf`` property ``object_base`` ile ayni degeri vermeli."""
    col = MSVCCompleteObjectLocator(
        addr=0x1000,
        signature=1,
        offset=0,
        cd_offset=0,
        type_descriptor=0x2000,
        class_hierarchy=0x3000,
        object_base=0x400,
    )
    assert col.pSelf == 0x400
    assert col.object_base == 0x400
    # Setter de calismali.
    col.pSelf = 0x500
    assert col.object_base == 0x500


def test_col_vftable_confidence_default_is_fallback():
    """Batch 6A: scan'dan gelen COL'un vftable_confidence=0.5 olmali
    (xref ile teyit edilmedi, col+ptr_size fallback)."""
    col = MSVCCompleteObjectLocator(
        addr=0x1000, signature=1, offset=0, cd_offset=0,
        type_descriptor=0x2000, class_hierarchy=0x3000,
    )
    assert col.vftable_confidence == 0.5
    assert col.image_base_validated is False


def test_resolve_vftable_from_xrefs_raises_confidence():
    """Batch 6A: Ghidra xref ile vftable dogrulanirsa confidence=1.0."""
    col = MSVCCompleteObjectLocator(
        addr=0x1000, signature=1, offset=0, cd_offset=0,
        type_descriptor=0x2000, class_hierarchy=0x3000,
        vftable_addr=0x1008, vftable_confidence=0.5,
    )
    parser = MSVCRTTIParser()
    xrefs = {0x1000: [0x5000]}  # COL'a isaret eden slot
    parser.resolve_vftable_addresses_from_xrefs([col], xrefs, pointer_size=8)
    assert col.vftable_confidence == 1.0
    # Xref'teki adres slot[-1]; vtable basi = ref + ptr_size
    assert col.vftable_addr == 0x5008


def test_scan_col_x64_validates_image_base():
    """Batch 6A: x64 COL'un pSelf'i image_base cross-check ile dogrulanmali."""
    image_base = 0x140000000
    rdata_va = image_base + 0x1000
    td_rva = 0x2000  # RVA, placeholder
    chd_rva = 0x3000

    td_va = image_base + td_rva
    # scan_type_descriptors TD'lerini tarar; basit set verelim
    td_obj = MSVCTypeDescriptor(
        addr=td_va, vftable_ptr=0, spare=0,
        name=".?AVTest@@", demangled="class Test",
    )
    tds = {td_va: td_obj}

    # COL offset'i -> col_va = rdata_va + off; pSelf = col_va - image_base
    # Placeholder: COL'u offset=0 konumlandiriyoruz.
    off = 0
    col_va = rdata_va + off
    pself_rva = col_va - image_base
    col_blob = (
        (1).to_bytes(4, "little")          # signature=1 x64
        + (0).to_bytes(4, "little")        # offset
        + (0).to_bytes(4, "little")        # cd_offset
        + td_rva.to_bytes(4, "little")     # pTD (RVA)
        + chd_rva.to_bytes(4, "little")    # pCHD (RVA)
        + pself_rva.to_bytes(4, "little")  # pSelf (RVA) — dogru!
    )
    binary = _make_binary_with_rdata(rdata_va, col_blob, image_base)
    parser = MSVCRTTIParser()
    cols = parser.scan_complete_object_locators(
        binary, tds, image_base, pointer_size=8,
    )
    assert len(cols) == 1
    c = cols[0]
    assert c.image_base_validated is True, (
        "pSelf=col_va-image_base olmasina ragmen validated=False"
    )
    assert c.pSelf == pself_rva


def test_scan_col_x64_detects_bogus_pself():
    """Batch 6A: pSelf tutarsiz ise validated=False kalmali."""
    image_base = 0x140000000
    rdata_va = image_base + 0x1000
    td_rva = 0x2000
    chd_rva = 0x3000
    td_va = image_base + td_rva
    tds = {td_va: MSVCTypeDescriptor(
        addr=td_va, vftable_ptr=0, spare=0,
        name=".?AVTest@@", demangled="class Test",
    )}
    off = 0
    col_va = rdata_va + off
    # Yanlis pSelf -> 1MB+ sapma
    bogus_pself = (col_va - image_base) + 0x200000
    col_blob = (
        (1).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + td_rva.to_bytes(4, "little")
        + chd_rva.to_bytes(4, "little")
        + bogus_pself.to_bytes(4, "little")
    )
    binary = _make_binary_with_rdata(rdata_va, col_blob, image_base)
    parser = MSVCRTTIParser()
    cols = parser.scan_complete_object_locators(
        binary, tds, image_base, pointer_size=8,
    )
    # Conservative: yine de COL eklenir ama validated=False.
    assert len(cols) == 1
    assert cols[0].image_base_validated is False
