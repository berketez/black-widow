"""DemanglerRegistry test suite.

Ortak demangler arabirimi ve dispatcher davranisini dogrular:
- Singleton: ``get_default_registry`` ayni instance'i dondurur.
- Rust mangled sembol -> rust adapter ile demangle.
- Go sembol -> go adapter ile demangle.
- C / mangled olmayan sembol -> None.
- ``register()`` ile yeni demangler eklenebilir; sirayla denenir.
- Hatali demangler registry'i bozmaz; sonraki demangler denenir.

Hicbir gercek binary gerekmez -- saf string testleri.
"""

from __future__ import annotations

import pytest

from karadul.analyzers.demangler_registry import (
    Demangler,
    DemanglerRegistry,
    GoDemanglerAdapter,
    RustDemanglerAdapter,
    _reset_default_registry_for_tests,
    get_default_registry,
)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_default() -> None:
    """Her test oncesinde default registry'i sifirla.

    Singleton'in test'ler arasi state sizdirmasini onler.
    """
    _reset_default_registry_for_tests()
    yield
    _reset_default_registry_for_tests()


# --------------------------------------------------------------------------
# Default registry / singleton
# --------------------------------------------------------------------------


class TestDefaultRegistry:
    """``get_default_registry`` davranisi."""

    def test_singleton_same_instance(self) -> None:
        """Iki cagri ayni nesneyi dondurmeli (lazy singleton)."""
        a = get_default_registry()
        b = get_default_registry()
        assert a is b

    def test_default_has_rust_and_go(self) -> None:
        """Default registry rust ve go demangler'lari icermeli."""
        reg = get_default_registry()
        formats = reg.list_formats()
        assert "rust" in formats
        assert "go" in formats
        # Rust once kayit edildigi icin daha onde olmali
        assert formats.index("rust") < formats.index("go")

    def test_reset_clears_singleton(self) -> None:
        """``_reset_default_registry_for_tests`` singleton'i sifirlamali."""
        a = get_default_registry()
        _reset_default_registry_for_tests()
        b = get_default_registry()
        assert a is not b


# --------------------------------------------------------------------------
# Rust dispatch
# --------------------------------------------------------------------------


class TestRustDispatch:
    """Rust mangled sembollerin rust adapter'ina yonlendirilmesi."""

    def test_legacy_itanium_demangle(self) -> None:
        """``_ZN...E`` formati demangle olmali ve format=rust donmeli."""
        reg = get_default_registry()
        result = reg.demangle_with_format(
            "_ZN4core3fmt5write17h1234567890abcdefE",
        )
        assert result is not None
        fmt, dem = result
        assert fmt == "rust"
        # core::fmt::write parcalarini icermeli; hash suffix elenmeli
        assert "core" in dem
        assert "fmt" in dem
        assert "write" in dem
        assert "h1234567890abcdef" not in dem

    def test_v0_mangled_demangle(self) -> None:
        """``_R...`` v0 sembolu rust adapter ile islenmeli."""
        reg = get_default_registry()
        # _RNvCs<base62>_3foo3bar formati: foo::bar parcalarini bekleriz
        result = reg.demangle_with_format("_RNvCs1234_3foo3bar")
        assert result is not None
        fmt, _dem = result
        assert fmt == "rust"

    def test_rust_demangle_only_returns_string(self) -> None:
        """``demangle`` sadece string'i dondurmeli, format etiketsiz."""
        reg = get_default_registry()
        out = reg.demangle("_ZN4core3fmt5writeE")
        assert isinstance(out, str)
        assert "core" in out


# --------------------------------------------------------------------------
# Go dispatch
# --------------------------------------------------------------------------


class TestGoDispatch:
    """Go sembollerin go adapter'ina yonlendirilmesi."""

    def test_pointer_receiver(self) -> None:
        """``pkg.(*Type).Method`` formati go olarak tanilanmali."""
        reg = get_default_registry()
        result = reg.demangle_with_format("time.(*Time).Format")
        assert result is not None
        fmt, dem = result
        assert fmt == "go"
        assert "Time" in dem
        assert "Format" in dem

    def test_top_level_func(self) -> None:
        """``pkg.Func`` Go top-level fonksiyonu."""
        reg = get_default_registry()
        result = reg.demangle_with_format("fmt.Println")
        assert result is not None
        fmt, dem = result
        assert fmt == "go"
        assert "Println" in dem


# --------------------------------------------------------------------------
# Negative cases
# --------------------------------------------------------------------------


class TestNoMatch:
    """Tanimlanamayan sembollerin None dondurmesi."""

    def test_c_function_returns_none(self) -> None:
        """Plain C fonksiyon adi hicbir demangler'a uymaz."""
        reg = get_default_registry()
        # Iceriginde nokta yok, mangled prefix yok -> hicbiri match etmez
        assert reg.demangle("printf") is None
        assert reg.demangle_with_format("printf") is None

    def test_empty_string(self) -> None:
        """Bos string None donmeli."""
        reg = get_default_registry()
        assert reg.demangle("") is None
        assert reg.demangle_with_format("") is None

    def test_non_string_input(self) -> None:
        """Non-str (None, int) None donmeli, exception atmamali."""
        reg = get_default_registry()
        assert reg.demangle(None) is None  # type: ignore[arg-type]
        assert reg.demangle(123) is None  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Adapter unit testleri
# --------------------------------------------------------------------------


class TestAdapters:
    """Adapter sinifi davranislari."""

    def test_rust_adapter_detect(self) -> None:
        """RustDemanglerAdapter.detect rust prefixlerini taniyor."""
        ad = RustDemanglerAdapter()
        assert ad.detect("_ZN4core3fmtE") is True
        assert ad.detect("_RNvCs1234_3foo") is True
        assert ad.detect("plain_c_func") is False
        assert ad.detect("") is False
        assert ad.format_name() == "rust"

    def test_go_adapter_detect(self) -> None:
        """GoDemanglerAdapter.detect Go heuristic'i ile calisiyor."""
        ad = GoDemanglerAdapter()
        assert ad.detect("fmt.Println") is True
        assert ad.detect("time.(*Time).Format") is True
        assert ad.detect("_ZN4coreE") is False  # Rust mangled, Go degil
        assert ad.detect("") is False
        assert ad.format_name() == "go"

    def test_rust_adapter_runtime_protocol(self) -> None:
        """Adapter Demangler protokolune uyuyor (runtime check)."""
        ad = RustDemanglerAdapter()
        assert isinstance(ad, Demangler)
        ad2 = GoDemanglerAdapter()
        assert isinstance(ad2, Demangler)


# --------------------------------------------------------------------------
# register() davranisi
# --------------------------------------------------------------------------


class _DummyDemangler:
    """Test icin sahte demangler. Belirli bir prefix'i tanir."""

    def __init__(self, prefix: str, label: str = "dummy") -> None:
        self._prefix = prefix
        self._label = label

    def detect(self, symbol: str) -> bool:
        return isinstance(symbol, str) and symbol.startswith(self._prefix)

    def demangle(self, symbol: str) -> str | None:
        if not self.detect(symbol):
            return None
        return f"{self._label}:{symbol[len(self._prefix):]}"

    def format_name(self) -> str:
        return self._label


class _CrashingDemangler:
    """``detect()`` icinde patlayan demangler -- registry sermemeli."""

    def detect(self, symbol: str) -> bool:
        raise RuntimeError("dummy crash")

    def demangle(self, symbol: str) -> str | None:
        raise RuntimeError("dummy crash")

    def format_name(self) -> str:
        return "crashy"


class TestRegister:
    """``DemanglerRegistry.register`` ve dispatch sirasi."""

    def test_register_and_dispatch(self) -> None:
        """Yeni demangler kaydedilebilir ve cagrilabilir."""
        reg = DemanglerRegistry()
        reg.register(_DummyDemangler(prefix="X_", label="dummy"))
        assert reg.list_formats() == ["dummy"]
        out = reg.demangle_with_format("X_hello")
        assert out == ("dummy", "dummy:hello")

    def test_register_multiple_first_match_wins(self) -> None:
        """Birden fazla demangler varsa ilk eslesen kullanilir."""
        reg = DemanglerRegistry()
        reg.register(_DummyDemangler(prefix="A_", label="alfa"))
        reg.register(_DummyDemangler(prefix="B_", label="beta"))
        assert reg.demangle_with_format("A_x") == ("alfa", "alfa:x")
        assert reg.demangle_with_format("B_y") == ("beta", "beta:y")
        assert reg.demangle_with_format("C_z") is None

    def test_register_none_raises(self) -> None:
        """None kaydetmek hata vermeli."""
        reg = DemanglerRegistry()
        with pytest.raises(ValueError):
            reg.register(None)  # type: ignore[arg-type]

    def test_register_invalid_object_raises(self) -> None:
        """Protocol metodlari eksik nesne TypeError ile reddedilmeli."""
        reg = DemanglerRegistry()

        class _Bad:
            pass

        with pytest.raises(TypeError):
            reg.register(_Bad())  # type: ignore[arg-type]

    def test_crashing_demangler_does_not_break_registry(self) -> None:
        """Detect/demangle icinde exception bir sonrakini bozmamali."""
        reg = DemanglerRegistry()
        reg.register(_CrashingDemangler())
        reg.register(_DummyDemangler(prefix="OK_", label="ok"))
        # Crashy bos donsun, ok'a dussun
        assert reg.demangle_with_format("OK_test") == ("ok", "ok:test")

    def test_fallback_when_detect_true_but_demangle_none(self) -> None:
        """Detect True ama demangle None ise sonraki demangler denenir."""
        reg = DemanglerRegistry()

        class _Greedy:
            """Her sembolu tanir ama hicbirini cozemez."""

            def detect(self, symbol: str) -> bool:
                return True

            def demangle(self, symbol: str) -> str | None:
                return None

            def format_name(self) -> str:
                return "greedy"

        reg.register(_Greedy())
        reg.register(_DummyDemangler(prefix="OK_", label="ok"))
        # Greedy detect=True dondurse de demangle=None oldugu icin
        # dispatcher sonraki demangler'a dusmeli.
        assert reg.demangle_with_format("OK_x") == ("ok", "ok:x")

    def test_len_and_repr(self) -> None:
        """``__len__`` ve ``__repr__`` calisiyor olmali."""
        reg = DemanglerRegistry()
        assert len(reg) == 0
        reg.register(_DummyDemangler(prefix="A_", label="a"))
        reg.register(_DummyDemangler(prefix="B_", label="b"))
        assert len(reg) == 2
        text = repr(reg)
        assert "a" in text and "b" in text
