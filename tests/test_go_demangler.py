"""Go demangler testleri.

karadul/analyzers/go_demangler.py modulu icin birim testleri. Saf algoritmik
demangling oldugu icin disk/binary fixture'a ihtiyac duyulmaz; bilinen Go
sembollerini girdi olarak kullaniriz.
"""

from __future__ import annotations

import pytest

from karadul.analyzers.go_demangler import (
    demangle,
    is_go_symbol,
    parse_symbol,
)


# ---------------------------------------------------------------------------
# is_go_symbol() heuristic testleri
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "symbol",
    [
        "main.main",
        "fmt.Println",
        "time.Time.Format",
        "time.(*Time).Format",
        "main.main.func1",
        "main.main.func1.1",
        "github.com/user/repo/pkg.Func",
        "slices.Sort[int]",
        "slices.Sort[go.shape.int_0]",
        "type..eq.[5]int",
        "type..hash.string",
        "runtime.gcMain",
        "runtime.morestack",
        "go.itab.*os.File,io.Reader",
        "_cgo_runtime_cgocall",
    ],
)
def test_is_go_symbol_positive(symbol: str) -> None:
    """Tipik Go sembollerinin tespit edildigini dogrula."""
    assert is_go_symbol(symbol) is True, f"{symbol!r} Go olarak tespit edilmedi"


@pytest.mark.parametrize(
    "symbol",
    [
        "_Z3fooi",                       # C++ Itanium
        "_ZN4core3fmt9Formatter3pad17h0E",  # Rust legacy
        "_RNvCs1_4testE",                # Rust v0
        "$s4main3fooyyF",                # Swift
        "?foo@@YAHXZ",                   # MSVC C++
        "printf",                         # plain C
        "main",                          # tek isim, nokta yok
        "",                              # bos
        "   ",                           # bosluk
    ],
)
def test_is_go_symbol_negative(symbol: str) -> None:
    """Go OLMAYAN sembollerin reddedildigini dogrula."""
    assert is_go_symbol(symbol) is False, f"{symbol!r} yanlis bicimde Go kabul edildi"


# ---------------------------------------------------------------------------
# parse_symbol() yapisal testleri
# ---------------------------------------------------------------------------


def test_parse_top_level_main() -> None:
    info = parse_symbol("main.main")
    assert info is not None
    assert info["package"] == "main"
    assert info["function"] == "main"
    assert info["is_method"] is False
    assert info["is_closure"] is False
    assert info["is_compiler_generated"] is False
    assert info["type"] is None
    assert info["receiver_kind"] is None
    assert info["generic_args"] is None


def test_parse_top_level_fmt_println() -> None:
    info = parse_symbol("fmt.Println")
    assert info is not None
    assert info["package"] == "fmt"
    assert info["function"] == "Println"
    assert info["is_method"] is False


def test_parse_value_receiver_method() -> None:
    info = parse_symbol("time.Time.Format")
    assert info is not None
    assert info["package"] == "time"
    assert info["type"] == "Time"
    assert info["receiver_kind"] == "value"
    assert info["function"] == "Format"
    assert info["is_method"] is True


def test_parse_pointer_receiver_method() -> None:
    info = parse_symbol("time.(*Time).Format")
    assert info is not None
    assert info["package"] == "time"
    assert info["type"] == "Time"
    assert info["receiver_kind"] == "pointer"
    assert info["function"] == "Format"
    assert info["is_method"] is True


def test_parse_pointer_receiver_with_full_path() -> None:
    info = parse_symbol("net/http.(*Server).ListenAndServe")
    assert info is not None
    assert info["package"] == "net/http"
    assert info["type"] == "Server"
    assert info["receiver_kind"] == "pointer"
    assert info["function"] == "ListenAndServe"
    assert info["is_method"] is True


def test_parse_closure_simple() -> None:
    info = parse_symbol("main.main.func1")
    assert info is not None
    assert info["is_closure"] is True
    # main.main.func1 bir method GIBI gozukmemeli (main kucuk harfle basliyor)
    # ama goyle parse edilirse (package=main, type=main, ...) — main kucuk
    # harfli oldugu icin VALUE_RECEIVER eslesmemeli.
    assert info["is_method"] is False
    assert info["package"] == "main"
    assert info["function"].startswith("main.func1")


def test_parse_nested_closure() -> None:
    info = parse_symbol("main.main.func1.1")
    assert info is not None
    assert info["is_closure"] is True


def test_parse_generic_simple() -> None:
    info = parse_symbol("slices.Sort[int]")
    assert info is not None
    assert info["package"] == "slices"
    assert info["function"] == "Sort"
    assert info["generic_args"] == ["int"]


def test_parse_generic_go_shape() -> None:
    info = parse_symbol("slices.Sort[go.shape.int_0]")
    assert info is not None
    assert info["generic_args"] == ["go.shape.int_0"]
    assert info["function"] == "Sort"


def test_parse_generic_multi_args() -> None:
    info = parse_symbol("maps.Clone[string,int]")
    assert info is not None
    assert info["generic_args"] == ["string", "int"]


def test_parse_compiler_generated_eq() -> None:
    info = parse_symbol("type..eq.[5]int")
    assert info is not None
    assert info["is_compiler_generated"] is True
    assert info["package"] == "type"


def test_parse_compiler_generated_hash() -> None:
    info = parse_symbol("type..hash.string")
    assert info is not None
    assert info["is_compiler_generated"] is True


def test_parse_runtime_symbol() -> None:
    info = parse_symbol("runtime.gcMain")
    assert info is not None
    assert info["package"] == "runtime"
    assert info["function"] == "gcMain"
    assert info["is_compiler_generated"] is True  # runtime.* compiler/runtime


def test_parse_path_with_github() -> None:
    info = parse_symbol("github.com/user/repo/pkg.Func")
    assert info is not None
    assert info["package"] == "github.com/user/repo/pkg"
    assert info["function"] == "Func"
    assert info["is_method"] is False


def test_parse_cgo_wrapper() -> None:
    info = parse_symbol("_cgo_runtime_cgocall")
    assert info is not None
    assert info["is_compiler_generated"] is True
    assert info["package"] == "cgo"


def test_parse_negative_cpp() -> None:
    assert parse_symbol("_Z3fooi") is None


def test_parse_negative_rust_v0() -> None:
    assert parse_symbol("_RNvCs1_4testE") is None


def test_parse_negative_plain_c() -> None:
    assert parse_symbol("printf") is None


def test_parse_negative_empty() -> None:
    assert parse_symbol("") is None
    assert parse_symbol("   ") is None


# ---------------------------------------------------------------------------
# demangle() insan-okunabilir cikti testleri
# ---------------------------------------------------------------------------


def test_demangle_top_level() -> None:
    assert demangle("main.main") == "main.main"


def test_demangle_pointer_receiver() -> None:
    out = demangle("time.(*Time).Format")
    assert out == "(*time.Time).Format"


def test_demangle_value_receiver() -> None:
    out = demangle("time.Time.Format")
    assert out == "time.Time.Format"


def test_demangle_generic() -> None:
    out = demangle("slices.Sort[int]")
    assert out == "slices.Sort[int]"


def test_demangle_compiler_generated_eq() -> None:
    out = demangle("type..eq.[5]int")
    assert out is not None
    assert "type equality" in out
    assert "[5]int" in out


def test_demangle_compiler_generated_hash() -> None:
    out = demangle("type..hash.string")
    assert out is not None
    assert "type hash" in out


def test_demangle_cgo() -> None:
    out = demangle("_cgo_runtime_cgocall")
    assert out is not None
    assert out.startswith("cgo wrapper")


def test_demangle_negative_returns_none() -> None:
    assert demangle("_Z3fooi") is None
    assert demangle("printf") is None
    assert demangle("") is None
