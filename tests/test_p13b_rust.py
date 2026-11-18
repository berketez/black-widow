"""P13b / IMZA-14: Rust ad ayrıştırıcı — legacy ``$…$`` kaçışları, C++ ayrımı, v0 punycode /
geri başvuru / sabit / ``::<``.

v0 beklenen değerleri bağımsız uygulamadan (LLVM ``llvm-cxxfilt``, bu makinede
``/opt/homebrew/opt/llvm/bin/llvm-cxxfilt``) alındı. Legacy için llvm-cxxfilt kaçışları çözmüyor
(Itanium ayrıştırıcısı); beklenenler rustc-demangle'ın ``legacy.rs`` kurallarıdır.
"""
from __future__ import annotations

import pytest

from karadul.analyzers import rust_demangler as RD

H = "17h0123456789abcdefE"


@pytest.fixture(autouse=True)
def _no_rustfilt(monkeypatch):
    monkeypatch.setattr(RD, "_resolve_rustfilt", lambda: None)


@pytest.mark.parametrize("sym, want", [
    (f"_ZN4core3ops8function6FnOnce9call_once28_$u7b$$u7b$closure$u7d$$u7d${H}",
     "core::ops::function::FnOnce::call_once::{{closure}}"),
    (f"_ZN4core3fmt3num52_$LT$impl$u20$core..fmt..Debug$u20$for$u20$usize$GT$3fmt{H}",
     "core::fmt::num::<impl core::fmt::Debug for usize>::fmt"),
    (f"__ZN5alloc5boxed12Box$LT$T$GT$3new{H}", "alloc::boxed::Box<T>::new"),
    (f"_ZN3foo8_$RF$str3bar{H}.llvm.123", "foo::&str::bar"),
])
def test_legacy_escapes_decoded(sym, want) -> None:
    assert RD.demangle(sym) == want


def test_legacy_unknown_escape_is_not_a_full_name() -> None:
    assert RD.demangle(f"_ZN3foo7bar$QQ$3baz{H}") is None


@pytest.mark.parametrize("sym", ["_ZN3foo3barEi", "_ZN3foo3barEd", "_ZN7MyClassC2Ev"])
def test_cpp_itanium_is_not_rust(sym) -> None:
    assert RD.demangle(sym) is None


@pytest.mark.parametrize("sym, want", [
    ("_RNvCs4fqI2P2rA04_11utf8_identsu30____7hkackfecea1cbdathfdh9qlzbm",
     "utf8_idents::ამელად_გეᄃმიელი_აფდᄂიᄂლი"),
    ("_RNvMNtCs1234_7mycrate3fooNtB2_3Bar3baz", "<mycrate::foo::Bar>::baz"),
    ("_RINvC7mycrate3fooKj7b_E", "mycrate::foo::<123>"),
    ("_RINvNtC3std3mem8align_ofjE", "std::mem::align_of::<usize>"),
    ("__RNvCsdBezzDwma51_7___rustc10rust_panic", "__rustc::rust_panic"),
])
def test_v0_matches_llvm_cxxfilt(sym, want) -> None:
    assert RD.demangle(sym) == want


def test_v0_unparsable_returns_none_not_placeholder() -> None:
    # ileri geri başvuru (hedef konum başvurunun kendisinden sonra) çözülemez
    assert RD.demangle("_RNvMNtCs1234_7mycrate3fooNtBz_3Bar3baz") is None
    # desteklenmeyen sabit türü (str): eski sezgisel yol "mycrate::foo::abc" uyduruyordu
    assert RD.demangle("_RINvC7mycrate3fooKe3abc_E") is None
