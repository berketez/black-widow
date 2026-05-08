"""Tests -- BinaryNinjaAdapter (v1.14 Dalga 2).

Binary Ninja Python SDK lisansli kurulum gerektirir; CI dahil cogu
test makinesinde import edilemez. Tum testler hermetik:

- Import edilemiyor pathway: ``_try_import_binaryninja`` monkeypatch ile
  None'a sabitlenir; ``RuntimeError("license required")`` beklenir.
- Happy path: sahte (mock) bir ``binaryninja`` modulu ve sahte
  ``BinaryView`` objesi ``monkeypatch.setattr`` ile saglanir.

Coverage (12 test):
    1. is_available() modul YOK -> False
    2. is_available() modul VAR -> True
    3. get_version() modul YOK -> None
    4. get_version() modul VAR + core_version() callable -> str
    5. extract_functions() modul YOK -> RuntimeError + "license required"
    6. extract_types() modul YOK -> RuntimeError + "license required"
    7. extract_all() modul YOK -> RuntimeError + "license required"
    8. extract_all() binary path yok -> RuntimeError ("binary path yok")
    9. extract_all() mocked happy path -> BNResult dolu (fn+type+meta)
    10. extract_functions() mocked -> BNFunction listesi
    11. extract_types() mocked -> BNType listesi (struct + enum)
    12. _convert_type kind detection -> struct/union/enum/typedef
    13. Dataclass smoke (BNFunction/BNType/BNResult defaults)
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from karadul.analyzers import binaryninja_adapter as bn_adapter
from karadul.analyzers.binaryninja_adapter import (
    BinaryNinjaAdapter,
    BNFunction,
    BNResult,
    BNType,
)


# ---------------------------------------------------------------------------
# Mock binaryninja modulu yardimcilari
# ---------------------------------------------------------------------------


class _FakeParameter:
    def __init__(self, name: str, type_repr: str) -> None:
        self.name = name
        self.type = type_repr


class _FakeSymbol:
    def __init__(self, sym_type: str = "") -> None:
        self.type = sym_type


class _FakeFunction:
    def __init__(
        self,
        *,
        name: str,
        start: int,
        size: int,
        return_type: str = "int",
        params: list[_FakeParameter] | None = None,
        is_thunk: bool = False,
        sym_type: str = "FunctionSymbol",
    ) -> None:
        self.name = name
        self.start = start
        self.total_bytes = size
        self.return_type = return_type
        self.parameter_vars = params or []
        self.is_thunk = is_thunk
        self.symbol = _FakeSymbol(sym_type)


class _FakeMember:
    def __init__(self, name: str, type_repr: str, offset: int) -> None:
        self.name = name
        self.type = type_repr
        self.offset = offset


class _FakeType:
    def __init__(
        self,
        *,
        type_class: str,
        width: int | None = None,
        members: list[_FakeMember] | None = None,
        repr_str: str = "",
    ) -> None:
        self.type_class = type_class
        self.width = width
        self.members = members or []
        self._repr = repr_str

    def __str__(self) -> str:  # pragma: no cover -- trivial
        return self._repr or f"<FakeType {self.type_class}>"


class _FakeTypes:
    """``bv.types`` -- dict-benzeri ``items()``."""

    def __init__(self, mapping: dict[str, _FakeType]) -> None:
        self._mapping = mapping

    def items(self) -> list[tuple[str, _FakeType]]:
        return list(self._mapping.items())


class _FakeBinaryView:
    def __init__(
        self,
        *,
        functions: list[_FakeFunction],
        types: dict[str, _FakeType],
        arch_name: str = "x86_64",
        platform_name: str = "windows-x86_64",
        entry_point: int = 0x401000,
    ) -> None:
        self.functions = functions
        self.types = _FakeTypes(types)
        self.arch = SimpleNamespace(name=arch_name)
        self.platform = SimpleNamespace(name=platform_name)
        self.entry_point = entry_point
        self.view_type = "PE"
        self.closed = False

    def file_close(self) -> None:  # pragma: no cover
        self.closed = True


def _make_fake_bn_module(bv: _FakeBinaryView, version: str = "binaryninja 4.2.6455") -> SimpleNamespace:
    """Sahte ``binaryninja`` modulu. ``load(path)`` -> bv don."""

    def _load(path: str, **_kwargs: Any) -> _FakeBinaryView:
        assert isinstance(path, str)
        return bv

    return SimpleNamespace(
        load=_load,
        core_version=lambda: version,
    )


# ---------------------------------------------------------------------------
# 1) is_available -- modul yok
# ---------------------------------------------------------------------------


def test_is_available_module_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: None)
    adapter = BinaryNinjaAdapter(tmp_path / "foo.exe")
    assert adapter.is_available() is False


# ---------------------------------------------------------------------------
# 2) is_available -- modul var
# ---------------------------------------------------------------------------


def test_is_available_module_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = SimpleNamespace(core_version=lambda: "4.2")
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: fake)
    adapter = BinaryNinjaAdapter(tmp_path / "foo.exe")
    assert adapter.is_available() is True


# ---------------------------------------------------------------------------
# 3) get_version -- yok ise None
# ---------------------------------------------------------------------------


def test_get_version_returns_none_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: None)
    adapter = BinaryNinjaAdapter(tmp_path / "foo.exe")
    assert adapter.get_version() is None


# ---------------------------------------------------------------------------
# 4) get_version -- mocked core_version
# ---------------------------------------------------------------------------


def test_get_version_returns_string_when_available(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake = SimpleNamespace(core_version=lambda: "4.2.6455-dev")
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: fake)
    adapter = BinaryNinjaAdapter(tmp_path / "foo.exe")
    assert adapter.get_version() == "4.2.6455-dev"


# ---------------------------------------------------------------------------
# 5-7) RuntimeError + "license required" mesaji modul yokken
# ---------------------------------------------------------------------------


def test_extract_functions_raises_when_module_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: None)
    adapter = BinaryNinjaAdapter(tmp_path / "foo.exe")
    with pytest.raises(RuntimeError, match="license required"):
        adapter.extract_functions()


def test_extract_types_raises_when_module_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: None)
    adapter = BinaryNinjaAdapter(tmp_path / "foo.exe")
    with pytest.raises(RuntimeError, match="license required"):
        adapter.extract_types()


def test_extract_all_raises_when_module_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: None)
    adapter = BinaryNinjaAdapter(tmp_path / "foo.exe")
    with pytest.raises(RuntimeError, match="license required"):
        adapter.extract_all()


# ---------------------------------------------------------------------------
# 8) extract_all -- modul var ama dosya yok
# ---------------------------------------------------------------------------


def test_extract_all_raises_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    fake_bv = _FakeBinaryView(functions=[], types={})
    fake_module = _make_fake_bn_module(fake_bv)
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: fake_module)
    adapter = BinaryNinjaAdapter(tmp_path / "absent.exe")
    with pytest.raises(RuntimeError, match="binary path yok"):
        adapter.extract_all()


# ---------------------------------------------------------------------------
# 9) extract_all -- mocked happy path
# ---------------------------------------------------------------------------


def test_extract_all_mocked_happy_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    bin_path = tmp_path / "foo.exe"
    bin_path.write_bytes(b"MZ\x00\x00")  # dummy

    fake_fn = _FakeFunction(
        name="MyFunction",
        start=0x401000,
        size=64,
        return_type="int",
        params=[_FakeParameter("arg0", "int")],
        sym_type="ImportedFunctionSymbol",
    )
    fake_struct = _FakeType(
        type_class="StructureTypeClass",
        width=24,
        members=[
            _FakeMember("a", "int", 0),
            _FakeMember("b", "char *", 8),
        ],
        repr_str="struct Foo { int a; char* b; }",
    )
    fake_bv = _FakeBinaryView(
        functions=[fake_fn],
        types={"Foo": fake_struct},
    )
    fake_module = _make_fake_bn_module(fake_bv)
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: fake_module)

    adapter = BinaryNinjaAdapter(bin_path)
    result = adapter.extract_all()

    assert isinstance(result, BNResult)
    assert result.binary_path == bin_path
    assert len(result.functions) == 1
    assert result.functions[0].name == "MyFunction"
    assert result.functions[0].address == 0x401000
    assert result.functions[0].is_imported is True
    assert result.functions[0].parameters == [{"name": "arg0", "type": "int"}]

    assert len(result.types) == 1
    bn_t = result.types[0]
    assert bn_t.name == "Foo"
    assert bn_t.kind == "struct"
    assert bn_t.size == 24
    assert len(bn_t.fields) == 2
    assert bn_t.fields[0]["offset"] == 0

    assert result.arch == "x86_64"
    assert result.platform == "windows"
    assert result.bv_summary["function_count"] == 1
    assert result.bv_summary["type_count"] == 1
    assert result.bv_summary["imported_function_count"] == 1
    assert result.bv_summary["entry_point"] == 0x401000
    assert result.duration_ms >= 0.0


# ---------------------------------------------------------------------------
# 10) extract_functions -- mocked
# ---------------------------------------------------------------------------


def test_extract_functions_mocked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    bin_path = tmp_path / "bar.elf"
    bin_path.write_bytes(b"\x7fELF")
    fake_fns = [
        _FakeFunction(name="main", start=0x1000, size=128),
        _FakeFunction(
            name="thunk_strlen",
            start=0x1100,
            size=8,
            is_thunk=True,
            sym_type="FunctionSymbol",
        ),
    ]
    fake_bv = _FakeBinaryView(functions=fake_fns, types={})
    fake_module = _make_fake_bn_module(fake_bv)
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: fake_module)

    adapter = BinaryNinjaAdapter(bin_path)
    fns = adapter.extract_functions()
    assert len(fns) == 2
    assert fns[0].name == "main"
    assert fns[0].size == 128
    assert fns[1].is_thunk is True


# ---------------------------------------------------------------------------
# 11) extract_types -- mocked (struct + enum)
# ---------------------------------------------------------------------------


def test_extract_types_mocked_struct_and_enum(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    bin_path = tmp_path / "baz.bin"
    bin_path.write_bytes(b"\x00\x00\x00\x00")
    types = {
        "Point": _FakeType(
            type_class="StructureTypeClass",
            width=16,
            members=[
                _FakeMember("x", "int", 0),
                _FakeMember("y", "int", 4),
            ],
        ),
        "Color": _FakeType(
            type_class="EnumerationTypeClass",
            width=4,
            members=[],
        ),
    }
    fake_bv = _FakeBinaryView(functions=[], types=types)
    fake_module = _make_fake_bn_module(fake_bv)
    monkeypatch.setattr(bn_adapter, "_try_import_binaryninja", lambda: fake_module)

    adapter = BinaryNinjaAdapter(bin_path)
    bn_types = adapter.extract_types()
    assert len(bn_types) == 2
    by_name = {t.name: t for t in bn_types}
    assert by_name["Point"].kind == "struct"
    assert by_name["Point"].size == 16
    assert by_name["Color"].kind == "enum"


# ---------------------------------------------------------------------------
# 12) _convert_type kind detection
# ---------------------------------------------------------------------------


def test_convert_type_kind_detection() -> None:
    cases = [
        ("StructureTypeClass", "struct"),
        ("UnionTypeClass", "union"),
        ("EnumerationTypeClass", "enum"),
        ("FunctionTypeClass", "function"),
        ("NamedTypeReferenceTypeClass", "typedef"),
        ("VoidTypeClass", "unknown"),
    ]
    for type_class, expected in cases:
        ttype = _FakeType(type_class=type_class)
        out = BinaryNinjaAdapter._convert_type("X", ttype)
        assert out.kind == expected, f"{type_class} -> {out.kind} (expected {expected})"


# ---------------------------------------------------------------------------
# 13) Dataclass smoke
# ---------------------------------------------------------------------------


def test_bnfunction_defaults() -> None:
    fn = BNFunction(name="foo", address=0x1000, size=64)
    assert fn.return_type is None
    assert fn.parameters == []
    assert fn.is_thunk is False
    assert fn.is_imported is False


def test_bntype_defaults() -> None:
    t = BNType(name="Foo", kind="struct")
    assert t.size is None
    assert t.fields == []
    assert t.raw == ""


def test_bnresult_defaults(tmp_path: Path) -> None:
    r = BNResult(binary_path=tmp_path / "x")
    assert r.functions == []
    assert r.types == []
    assert r.arch is None
    assert r.platform is None
    assert r.bv_summary == {}
    assert r.duration_ms == 0.0


# ---------------------------------------------------------------------------
# Real binary smoke -- skip if binaryninja import edilemiyor
# ---------------------------------------------------------------------------


def _bn_actually_importable() -> bool:
    try:
        import binaryninja  # noqa: F401
    except Exception:
        return False
    return True


@pytest.mark.skipif(
    not _bn_actually_importable(),
    reason="binaryninja module not available -- license required",
)
def test_real_bn_version_smoke(tmp_path: Path) -> None:  # pragma: no cover
    adapter = BinaryNinjaAdapter(tmp_path / "nonexistent.exe")
    version = adapter.get_version()
    assert version is None or isinstance(version, str)
