"""Tests for karadul.analyzers.cpp_rtti -- Itanium ABI RTTI/vtable parser.

Coverage (v1.10.0 M3 T9):
- CppClass / ClassHierarchy dataclass'lari
- demangle_itanium: cxxfilt + c++filt fallback + unknown fallback
- RTTIParser.parse_itanium: empty symbols, mock symbols (single class, inheritance chain)
- VTableReconstructor.build + format_methods
- ClassHierarchy.get_method_binding: valid, invalid offset, missing class
- read_vtable_entries: basic okuma, section yok, icerik kisa, zero entry

Fixture yaklasimi: Gercek C++ binary yok; mock lief.Binary objesi
(MagicMock + custom section_from_virtual_address) ve elle hazirlanmis
sembol dict'leri kullaniyoruz. Integration icin fixtures/sample_cpp
eklemek v1.10.1'de opsiyonel.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.cpp_rtti import (
    ClassHierarchy,
    CppClass,
    RTTIParser,
    VTableReconstructor,
    _class_name_from_typeinfo,
    _method_name_from_mangled,
    _strip_macho_underscore,
    demangle_itanium,
    read_vtable_entries,
)


# ------------------------------------------------------------------
# Dataclass testleri
# ------------------------------------------------------------------

def test_cpp_class_dataclass():
    """CppClass temel alanlarinin duzgun init edildigini dogrular."""
    cls = CppClass(
        name="MyClass",
        mangled_name="_ZTI7MyClass",
        typeinfo_addr="0x1000",
        vtable_addr="0x2000",
    )
    assert cls.name == "MyClass"
    assert cls.mangled_name == "_ZTI7MyClass"
    assert cls.typeinfo_addr == "0x1000"
    assert cls.vtable_addr == "0x2000"
    # Default factory'ler
    assert cls.methods == []
    assert cls.base_classes == []


def test_class_hierarchy_dataclass():
    """ClassHierarchy dataclass ve address_to_class lookup."""
    h = ClassHierarchy()
    assert h.classes == []
    assert h.address_to_class == {}

    cls = CppClass("A", "_ZTI1A", "0x1", "0x2")
    h.classes.append(cls)
    h.address_to_class["0x2"] = cls
    assert len(h.classes) == 1
    assert h.address_to_class["0x2"] is cls


# ------------------------------------------------------------------
# Demangling testleri
# ------------------------------------------------------------------

def test_demangle_itanium_with_cxxfilt():
    """cxxfilt mevcutsa Itanium mangled ismi demangle eder."""
    # _ZN7MyClass3fooEv -> "MyClass::foo()"
    result = demangle_itanium("_ZN7MyClass3fooEv")
    assert "MyClass" in result
    assert "foo" in result


def test_demangle_itanium_fallback_subprocess():
    """cxxfilt yoksa c++filt subprocess fallback'i calisir."""
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = "MyClass::foo()\n"

    # cxxfilt yokmus gibi ImportError raise et
    import builtins
    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "cxxfilt":
            raise ImportError("simulated no cxxfilt")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=blocked_import), \
         patch("subprocess.run", return_value=fake_result) as mock_run:
        result = demangle_itanium("_ZN7MyClass3fooEv")
    assert result == "MyClass::foo()"
    args = mock_run.call_args[0][0]
    # v1.10.0 Fix Sprint HIGH-4: argv injection onleme icin '--'
    # end-of-options marker eklendi; mangled symbol argv[2] oldu.
    assert args[0] == "c++filt"
    assert args[1] == "--"
    assert args[2] == "_ZN7MyClass3fooEv"


def test_demangle_unknown_fallback():
    """Demangle edilemeyen (gecersiz) sembol orijinal hali ile doner."""
    # Hem cxxfilt InvalidName raise etsin hem de c++filt none dondursun
    result = demangle_itanium("not_a_mangled_symbol")
    # cxxfilt InvalidName veya c++filt "not_a_mangled_symbol" demangle edemez ->
    # orijinal string dondurulur (cxxfilt case) VEYA ayni string c++filt'ten doner.
    # Her iki durumda da orijinal string beklenir.
    assert result == "not_a_mangled_symbol"


def test_demangle_empty_string():
    """Bos string -> bos string."""
    assert demangle_itanium("") == ""


def test_strip_macho_underscore():
    """Mach-O '_' prefix handling."""
    assert _strip_macho_underscore("__ZTI7MyClass") == "_ZTI7MyClass"
    assert _strip_macho_underscore("_ZTI7MyClass") == "_ZTI7MyClass"  # zaten tek
    assert _strip_macho_underscore("other_symbol") == "other_symbol"


def test_class_name_from_typeinfo():
    """_ZTI<m> -> demangled sinif ismi."""
    assert _class_name_from_typeinfo("_ZTI7MyClass") == "MyClass"


def test_method_name_from_mangled_demangles():
    """Metod mangled -> okunabilir demangled isim."""
    result = _method_name_from_mangled("_ZN7MyClass3fooEv")
    assert "foo" in result


# ------------------------------------------------------------------
# RTTIParser testleri
# ------------------------------------------------------------------

def test_parse_itanium_no_rtti_symbols(tmp_path: Path):
    """RTTI sembolu yok -> empty hierarchy."""
    parser = RTTIParser(config=None)
    # Sembol dict'i bos -> lief yolu calismaz, direkt empty doner
    binary_path = tmp_path / "fake.so"
    binary_path.write_bytes(b"not a real binary")
    hierarchy = parser.parse_itanium(binary_path, symbols={}, binary=None)
    assert isinstance(hierarchy, ClassHierarchy)
    assert hierarchy.classes == []
    assert hierarchy.address_to_class == {}


def test_parse_itanium_mock_symbols_single_class(tmp_path: Path):
    """_ZTI7MyClass + _ZTV7MyClass semboller + mock binary -> 1 class."""
    parser = RTTIParser(config=None)
    binary_path = tmp_path / "fake.so"
    binary_path.write_bytes(b"placeholder")

    symbols = {
        "_ZTI7MyClass": 0x1000,
        "_ZTV7MyClass": 0x2000,
        "_ZN7MyClass3fooEv": 0x3000,
        "_ZN7MyClass3barEv": 0x3100,
    }
    # Mock binary: vtable slot'larini [0, typeinfo_ptr, 0x3000, 0x3100, 0] olarak ver
    section = MagicMock()
    section.virtual_address = 0x2000
    # 5 slot x 8 byte = 40 byte
    section.content = (
        (0).to_bytes(8, "little")          # offset-to-top
        + (0x1000).to_bytes(8, "little")    # typeinfo ptr
        + (0x3000).to_bytes(8, "little")    # &foo
        + (0x3100).to_bytes(8, "little")    # &bar
        + (0).to_bytes(8, "little")         # NULL terminator
    )
    fake_binary = MagicMock()
    fake_binary.section_from_virtual_address.return_value = section

    hierarchy = parser.parse_itanium(binary_path, symbols=symbols, binary=fake_binary)
    assert len(hierarchy.classes) == 1
    cls = hierarchy.classes[0]
    assert cls.name == "MyClass"
    assert cls.mangled_name == "_ZTI7MyClass"
    assert cls.typeinfo_addr == "0x1000"
    assert cls.vtable_addr == "0x2000"
    # 2 metod (foo, bar) -- NULL entry'de kesildi
    assert len(cls.methods) == 2
    # Slot 0: foo
    assert cls.methods[0]["offset_in_vtable"] == 0
    assert cls.methods[0]["addr"] == "0x3000"
    assert "foo" in cls.methods[0]["name"]
    # Slot 1: bar
    assert cls.methods[1]["offset_in_vtable"] == 1
    assert "bar" in cls.methods[1]["name"]
    # address_to_class lookup
    assert "0x2000" in hierarchy.address_to_class


def test_parse_itanium_typeinfo_without_vtable(tmp_path: Path):
    """_ZTI var ama _ZTV yok (abstract/forward decl) -> class olusur, vtable_addr bos."""
    parser = RTTIParser(config=None)
    binary_path = tmp_path / "fake.so"
    binary_path.write_bytes(b"placeholder")
    symbols = {"_ZTI8Abstract": 0x1000}

    hierarchy = parser.parse_itanium(binary_path, symbols=symbols, binary=None)
    assert len(hierarchy.classes) == 1
    cls = hierarchy.classes[0]
    assert cls.name == "Abstract"
    assert cls.vtable_addr == ""
    assert cls.methods == []
    # vtable_addr bos ise address_to_class'a eklenmez
    assert "0x1000" not in hierarchy.address_to_class


def test_parse_itanium_macho_underscore_prefix(tmp_path: Path):
    """Mach-O sembolleri __Z... prefix'li olarak gelebilir, strip edilip islenir."""
    parser = RTTIParser(config=None)
    binary_path = tmp_path / "fake.dylib"
    binary_path.write_bytes(b"placeholder")
    symbols = {
        "__ZTI7MyClass": 0x1000,  # double underscore Mach-O
        "__ZTV7MyClass": 0x2000,
    }
    hierarchy = parser.parse_itanium(binary_path, symbols=symbols, binary=None)
    assert len(hierarchy.classes) == 1
    assert hierarchy.classes[0].name == "MyClass"


# ------------------------------------------------------------------
# VTableReconstructor testleri
# ------------------------------------------------------------------

def test_vtable_reconstructor_basic():
    """build() + format_methods() ile metod listesi olusumu."""
    rec = VTableReconstructor(config=None)
    cls = CppClass(
        name="MyClass",
        mangled_name="_ZTI7MyClass",
        typeinfo_addr="0x1000",
        vtable_addr="0x2000",
    )
    section = MagicMock()
    section.virtual_address = 0x2000
    section.content = (
        (0).to_bytes(8, "little")
        + (0x1000).to_bytes(8, "little")
        + (0xAAAA).to_bytes(8, "little")
        + (0xBBBB).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
    )
    fake_binary = MagicMock()
    fake_binary.section_from_virtual_address.return_value = section

    symbols = {
        "_ZN7MyClass1aEv": 0xAAAA,
        "_ZN7MyClass1bEv": 0xBBBB,
    }
    method_map = rec.build(cls, fake_binary, symbols)
    assert 0xAAAA in method_map
    assert 0xBBBB in method_map

    formatted = rec.format_methods(method_map)
    assert len(formatted) == 2
    assert formatted[0]["offset_in_vtable"] == 0
    assert formatted[1]["offset_in_vtable"] == 1
    assert all("addr" in m and "name" in m for m in formatted)


def test_vtable_reconstructor_unresolved_slot():
    """Sembolde bulunmayan pointer -> sub_<addr> placeholder."""
    rec = VTableReconstructor(config=None)
    cls = CppClass("X", "_ZTI1X", "0x1000", "0x2000")
    section = MagicMock()
    section.virtual_address = 0x2000
    section.content = (
        (0).to_bytes(8, "little")
        + (0x1000).to_bytes(8, "little")
        + (0xDEAD).to_bytes(8, "little")   # bu sembolde yok
        + (0).to_bytes(8, "little")
    )
    fake_binary = MagicMock()
    fake_binary.section_from_virtual_address.return_value = section
    method_map = rec.build(cls, fake_binary, symbols={})
    assert method_map[0xDEAD].startswith("sub_")


def test_vtable_reconstructor_no_vtable_addr():
    """vtable_addr bos ise build() empty dict dondurur."""
    rec = VTableReconstructor(config=None)
    cls = CppClass("X", "_ZTI1X", "0x1000", "")
    assert rec.build(cls, MagicMock(), {}) == {}


# ------------------------------------------------------------------
# read_vtable_entries testleri
# ------------------------------------------------------------------

def test_read_vtable_entries_basic():
    """Basit okuma: 3 pointer entry."""
    section = MagicMock()
    section.virtual_address = 0x1000
    section.content = (
        (0xAA).to_bytes(8, "little")
        + (0xBB).to_bytes(8, "little")
        + (0xCC).to_bytes(8, "little")
    )
    fake_binary = MagicMock()
    fake_binary.section_from_virtual_address.return_value = section
    entries = read_vtable_entries(fake_binary, 0x1000, 3)
    assert entries == [0xAA, 0xBB, 0xCC]


def test_read_vtable_entries_no_section():
    """section_from_virtual_address None donerse empty list."""
    fake_binary = MagicMock()
    fake_binary.section_from_virtual_address.return_value = None
    assert read_vtable_entries(fake_binary, 0x1000, 3) == []


def test_read_vtable_entries_zero_count():
    """count=0 veya negatif -> empty."""
    fake_binary = MagicMock()
    assert read_vtable_entries(fake_binary, 0x1000, 0) == []
    assert read_vtable_entries(fake_binary, 0x1000, -5) == []


def test_read_vtable_entries_content_too_short():
    """Content yetersizse kismi okur (erken break)."""
    section = MagicMock()
    section.virtual_address = 0x1000
    # Sadece 12 byte: 1.5 entry
    section.content = (0xAA).to_bytes(8, "little") + b"\x00\x00\x00\x00"
    fake_binary = MagicMock()
    fake_binary.section_from_virtual_address.return_value = section
    entries = read_vtable_entries(fake_binary, 0x1000, 5)
    assert entries == [0xAA]


# ------------------------------------------------------------------
# ClassHierarchy.get_method_binding testleri
# ------------------------------------------------------------------

def test_get_method_binding_valid():
    """Valid vtable+offset -> (class_name, method_name)."""
    cls = CppClass("MyClass", "_ZTI7MyClass", "0x1", "0x2000")
    cls.methods = [
        {"name": "foo", "addr": "0x3000", "offset_in_vtable": 0},
        {"name": "bar", "addr": "0x3100", "offset_in_vtable": 1},
    ]
    h = ClassHierarchy(classes=[cls], address_to_class={"0x2000": cls})
    assert h.get_method_binding("0x2000", 0) == ("MyClass", "foo")
    assert h.get_method_binding("0x2000", 1) == ("MyClass", "bar")


def test_get_method_binding_invalid_offset():
    """Bilinmeyen offset -> None."""
    cls = CppClass("X", "_ZTI1X", "0x1", "0x2000")
    cls.methods = [{"name": "foo", "addr": "0x3000", "offset_in_vtable": 0}]
    h = ClassHierarchy(classes=[cls], address_to_class={"0x2000": cls})
    assert h.get_method_binding("0x2000", 42) is None


def test_get_method_binding_missing_vtable():
    """Bilinmeyen vtable_addr -> None."""
    h = ClassHierarchy()
    assert h.get_method_binding("0xDEAD", 0) is None


# ------------------------------------------------------------------
# Config entegrasyonu
# ------------------------------------------------------------------

def test_rtti_config_defaults():
    """BinaryReconstructionConfig yeni RTTI alanlari default'u."""
    from karadul.config import BinaryReconstructionConfig
    cfg = BinaryReconstructionConfig()
    assert cfg.enable_rtti_recovery is False
    assert cfg.rtti_abi == "itanium"
    assert cfg.rtti_max_vtable_entries == 64


def test_rtti_parser_reads_max_entries_from_config():
    """RTTIParser rtti_max_vtable_entries config'i okumali."""
    cfg = MagicMock()
    cfg.rtti_max_vtable_entries = 16
    parser = RTTIParser(cfg)
    assert parser._max_entries == 16

    rec = VTableReconstructor(cfg)
    assert rec._max_entries == 16
