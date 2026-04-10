"""Rust Binary Analyzer test suite.

Rust symbol demangling, panic handler tespiti, crate extraction
ve Rust string pattern detection testleri.

Gercek Rust binary olmadan calismali -- mock data kullanir.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.rust_binary import (
    RustBinaryAnalyzer,
    _PANIC_PATTERNS,
    _RUST_MANGLED_PATTERN,
)
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def config() -> Config:
    """Test icin varsayilan Config."""
    return Config()


@pytest.fixture
def rust_analyzer(config: Config) -> RustBinaryAnalyzer:
    """RustBinaryAnalyzer instance."""
    return RustBinaryAnalyzer(config)


@pytest.fixture
def mock_rust_binary(tmp_path: Path) -> Path:
    """Sahte Rust binary olustur — Rust runtime string'leri iceren."""
    binary_path = tmp_path / "test_rust_binary"

    content = b"\x00" * 64  # padding
    content += b"rust_begin_unwind\x00"
    content += b"rust_panic\x00"
    content += b"core::panicking::panic\x00"
    content += b"core::panicking::panic_fmt\x00"
    content += b"std::panicking::begin_panic\x00"
    content += b"core::result::unwrap_failed\x00"
    content += b'called `Result::unwrap()` on an `Err` value\x00'
    content += b'called `Option::unwrap()` on a `None` value\x00'
    content += b"panicked at 'index out of bounds'\x00"
    content += b"thread 'main' panicked at\x00"
    content += b"/Users/user/.cargo/registry/src/github.com-xxx/serde-1.0.160/src/lib.rs\x00"
    content += b"Cargo.toml\x00"
    content += b"_ZN4core3fmt5write17h1234567890abcdefE\x00"
    content += b"_ZN3std2io5Write9write_all17habcdefg123456789E\x00"
    content += b"_ZN4rand4rngs6thread12thread_rng17h9876543210fedcbaE\x00"
    content += b"rustc\x00"
    content += b"\x00" * 64  # padding

    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def mock_rust_target(mock_rust_binary: Path) -> TargetInfo:
    """TargetInfo instance for Rust binary."""
    return TargetInfo(
        path=mock_rust_binary,
        name="test_rust_binary",
        target_type=TargetType.MACHO_BINARY,
        language=Language.RUST,
        file_size=mock_rust_binary.stat().st_size,
        file_hash="abc123",
        metadata={"magic": "0xFEEDFACF"},
    )


@pytest.fixture
def mock_workspace(tmp_path: Path) -> Workspace:
    """Gecici workspace."""
    ws = Workspace(tmp_path / "workspaces", "test_rust")
    ws.create()
    return ws


@pytest.fixture
def sample_symbols() -> list[dict[str, Any]]:
    """Ornek symbol listesi — Rust mangled isimleri iceren."""
    return [
        {"name": "_ZN4core3fmt5write17h1234567890abcdefE", "address": "0x100001000", "type": "T"},
        {"name": "_ZN3std2io5Write9write_all17habcdefg123456789E", "address": "0x100002000", "type": "T"},
        {"name": "_ZN4rand4rngs6thread12thread_rng17h9876543210fedcbaE", "address": "0x100003000", "type": "T"},
        {"name": "_ZN4core9panicking5panic17hfedcba0987654321E", "address": "0x100004000", "type": "T"},
        {"name": "_ZN3std10sys_common9backtrace28__rust_begin_short_backtrace17h1111222233334444E", "address": "0x100005000", "type": "T"},
        {"name": "some_c_function", "address": "0x100006000", "type": "T"},
        {"name": "", "address": "0x100007000", "type": "U"},
        {"name": "_RNvNtCs12345_4rand4rngs10thread_rng", "address": "0x100008000", "type": "T"},
    ]


# --------------------------------------------------------------------------
# Demangling Tests
# --------------------------------------------------------------------------

class TestRustDemangling:
    """Rust symbol demangling testleri."""

    def test_itanium_basic_demangling(self, rust_analyzer: RustBinaryAnalyzer):
        """Basit Itanium ABI demangling calismali."""
        result = rust_analyzer._demangle_rust("_ZN4core3fmt5write17h1234567890abcdefE")
        # core::fmt::write (hash suffix cikarilmis olmali)
        assert "core" in result
        assert "fmt" in result
        assert "write" in result

    def test_itanium_std_io(self, rust_analyzer: RustBinaryAnalyzer):
        """std::io::Write::write_all demangling."""
        result = rust_analyzer._demangle_rust("_ZN3std2io5Write9write_all17habcdefg123456789E")
        assert "std" in result
        assert "io" in result
        assert "write_all" in result

    def test_demangling_non_rust_symbol(self, rust_analyzer: RustBinaryAnalyzer):
        """Rust olmayan symbol oldugu gibi donmeli."""
        result = rust_analyzer._demangle_rust("some_c_function")
        assert result == "some_c_function"

    def test_demangling_empty_string(self, rust_analyzer: RustBinaryAnalyzer):
        """Bos string oldugu gibi donmeli."""
        result = rust_analyzer._demangle_rust("")
        assert result == ""

    def test_itanium_static_parser(self):
        """Itanium parser parcalari dogru ayirmali."""
        result = RustBinaryAnalyzer._demangle_itanium("4core3fmt5writeE")
        assert result == "core::fmt::write"

    def test_itanium_hash_suffix_removal(self):
        """Hash suffix (17h...) cikarilmali."""
        result = RustBinaryAnalyzer._demangle_itanium(
            "4core3fmt5write17h1234567890abcdefE"
        )
        # Hash suffix cikarilmis olmali
        assert "h1234567890abcdef" not in result
        assert "core" in result

    def test_demangle_symbols_list(self, rust_analyzer: RustBinaryAnalyzer, sample_symbols: list):
        """Symbol listesi toplu demangling."""
        result = rust_analyzer._demangle_symbols(sample_symbols)

        assert result is not None
        assert result["total"] > 0
        assert result["demangled_count"] > 0
        assert len(result["symbols"]) > 0

        # Her demangled symbol original ve demangled alanlarina sahip olmali
        for sym in result["symbols"]:
            assert "original" in sym
            assert "demangled" in sym

    def test_v0_mangling_detection(self):
        """Rust mangling pattern'leri tanilanmali."""
        # Itanium ABI (eski Rust): _ZN + rakam
        assert _RUST_MANGLED_PATTERN.match("_ZN4core3fmt5writeE")
        assert _RUST_MANGLED_PATTERN.match("_ZN3std2io5Write9write_allE")

        # v0 mangling: _RN + rakam (ornek: _RN3std...)
        assert _RUST_MANGLED_PATTERN.match("_RN3std2io5WriteE")

        # v0 mangling farkli formatta olanlar (_RNv...) pattern'a uymuyor
        # cunku _RN'den sonra rakam yerine harf var
        assert not _RUST_MANGLED_PATTERN.match("_RNvNtCs12345_4rand4rngs10thread_rng")

        # C fonksiyonlari uymamali
        assert not _RUST_MANGLED_PATTERN.match("some_c_function")
        assert not _RUST_MANGLED_PATTERN.match("printf")


# --------------------------------------------------------------------------
# Crate Extraction Tests
# --------------------------------------------------------------------------

class TestCrateExtraction:
    """Rust crate ismi cikarma testleri."""

    def test_extract_crates_basic(self, rust_analyzer: RustBinaryAnalyzer, sample_symbols: list):
        """Symbol isimlerinden crate isimleri cikarilmali."""
        result = rust_analyzer._extract_crates(sample_symbols)

        assert result is not None
        assert result["total"] > 0

        crate_names = [c["name"] for c in result["crates"]]
        assert "core" in crate_names
        assert "std" in crate_names
        assert "rand" in crate_names

    def test_extract_crates_with_counts(self, rust_analyzer: RustBinaryAnalyzer, sample_symbols: list):
        """Her crate icin symbol sayisi dogru olmali."""
        result = rust_analyzer._extract_crates(sample_symbols)

        crate_map = {c["name"]: c["symbol_count"] for c in result["crates"]}
        # core crate'inde en az 2 symbol var (core::fmt::write + core::panicking::panic)
        assert crate_map.get("core", 0) >= 2

    def test_extract_crates_empty_symbols(self, rust_analyzer: RustBinaryAnalyzer):
        """Bos symbol listesi icin bos crate listesi."""
        result = rust_analyzer._extract_crates([])
        assert result["total"] == 0
        assert result["crates"] == []

    def test_extract_crates_no_rust_symbols(self, rust_analyzer: RustBinaryAnalyzer):
        """Rust olmayan symbollerden crate cikmamali."""
        symbols = [
            {"name": "printf", "address": "0x1000", "type": "T"},
            {"name": "main", "address": "0x2000", "type": "T"},
        ]
        result = rust_analyzer._extract_crates(symbols)
        assert result["total"] == 0


# --------------------------------------------------------------------------
# Panic Handler Detection Tests
# --------------------------------------------------------------------------

class TestPanicDetection:
    """Panic handler tespiti testleri."""

    def test_detect_panic_handlers(self, rust_analyzer: RustBinaryAnalyzer):
        """Bilinen panic handler symbol'leri tespit edilmeli."""
        symbols = [
            {"name": "core::panicking::panic", "address": "0x1000"},
            {"name": "std::panicking::begin_panic", "address": "0x2000"},
            {"name": "core::result::unwrap_failed", "address": "0x3000"},
            {"name": "main::do_something", "address": "0x4000"},
        ]

        found = rust_analyzer._detect_panic_handlers(symbols)

        assert len(found) == 3
        patterns_found = [f["pattern"] for f in found]
        assert "core::panicking::panic" in patterns_found
        assert "std::panicking::begin_panic" in patterns_found
        assert "core::result::unwrap_failed" in patterns_found

    def test_no_panic_handlers(self, rust_analyzer: RustBinaryAnalyzer):
        """Panic handler yoksa bos liste."""
        symbols = [
            {"name": "main::safe_function", "address": "0x1000"},
        ]
        found = rust_analyzer._detect_panic_handlers(symbols)
        assert found == []

    def test_panic_patterns_constant(self):
        """Panic pattern listesi bos olmamali."""
        assert len(_PANIC_PATTERNS) > 0
        assert "rust_begin_unwind" in _PANIC_PATTERNS
        assert "core::panicking::panic" in _PANIC_PATTERNS


# --------------------------------------------------------------------------
# Rust String Pattern Tests
# --------------------------------------------------------------------------

class TestRustStringPatterns:
    """Rust-spesifik string pattern detection testleri."""

    def test_find_unwrap_patterns(self, rust_analyzer: RustBinaryAnalyzer):
        """Result/Option unwrap pattern'leri bulunmali."""
        strings = [
            "called `Result::unwrap()` on an `Err` value",
            "called `Option::unwrap()` on a `None` value",
            "some random string",
        ]

        result = rust_analyzer._find_rust_strings(strings)

        assert result is not None
        assert result["total"] >= 2

        categories = [p["category"] for p in result["patterns"]]
        assert "unwrap_pattern" in categories

    def test_find_panic_messages(self, rust_analyzer: RustBinaryAnalyzer):
        """Panic mesajlari bulunmali."""
        strings = [
            "panicked at 'index out of bounds'",
            "thread 'main' panicked at 'unwrap failed'",
        ]

        result = rust_analyzer._find_rust_strings(strings)

        assert result is not None
        categories = [p["category"] for p in result["patterns"]]
        assert "panic_message" in categories or "thread_panic" in categories

    def test_find_cargo_references(self, rust_analyzer: RustBinaryAnalyzer):
        """Cargo.toml referanslari bulunmali."""
        strings = [
            "/Users/user/.cargo/registry/src/github.com-xxx/serde-1.0.160/src/lib.rs",
            "Cargo.toml",
        ]

        result = rust_analyzer._find_rust_strings(strings)

        assert result is not None
        categories = [p["category"] for p in result["patterns"]]
        assert "cargo_reference" in categories or "cargo_registry" in categories

    def test_find_std_references(self, rust_analyzer: RustBinaryAnalyzer):
        """std library referanslari bulunmali."""
        strings = [
            "std::io::Error",
            "core::fmt::Display",
            "alloc::vec::Vec",
        ]

        result = rust_analyzer._find_rust_strings(strings)

        assert result is not None
        categories = [p["category"] for p in result["patterns"]]
        assert any(c in categories for c in ("std_reference", "core_fmt", "alloc_reference"))

    def test_no_rust_strings(self, rust_analyzer: RustBinaryAnalyzer):
        """Rust string'i yoksa bos sonuc."""
        strings = ["hello world", "just a normal string"]

        result = rust_analyzer._find_rust_strings(strings)

        assert result is not None
        assert result["total"] == 0

    def test_category_stats(self, rust_analyzer: RustBinaryAnalyzer):
        """Kategori istatistikleri dogru hesaplanmali."""
        strings = [
            "called `Result::unwrap()` on an `Err` value",
            "called `Option::unwrap()` on a `None` value",
            "panicked at 'test failed'",
            "std::io::Error",
        ]

        result = rust_analyzer._find_rust_strings(strings)

        assert result is not None
        assert "category_stats" in result
        assert sum(result["category_stats"].values()) == result["total"]


# --------------------------------------------------------------------------
# Rustfilt Check Test
# --------------------------------------------------------------------------

class TestRustfiltCheck:
    """rustfilt tool kontrol testi."""

    def test_rustfilt_available(self, rust_analyzer: RustBinaryAnalyzer):
        """rustfilt mevcutsa True donmeli."""
        mock_result = MagicMock()
        mock_result.success = True

        with patch.object(rust_analyzer.runner, "run_command", return_value=mock_result):
            assert rust_analyzer._check_rustfilt() is True

    def test_rustfilt_not_available(self, rust_analyzer: RustBinaryAnalyzer):
        """rustfilt yoksa False donmeli."""
        mock_result = MagicMock()
        mock_result.success = False

        with patch.object(rust_analyzer.runner, "run_command", return_value=mock_result):
            assert rust_analyzer._check_rustfilt() is False


# --------------------------------------------------------------------------
# Integration: analyze_static (mock)
# --------------------------------------------------------------------------

class TestRustStaticAnalysis:
    """Tam statik analiz testi (mock ile)."""

    def test_analyze_static_with_rust_data(
        self,
        rust_analyzer: RustBinaryAnalyzer,
        mock_rust_target: TargetInfo,
        mock_workspace: Workspace,
        sample_symbols: list,
    ):
        """Rust ek analizi basarili calismali."""
        # MachO ana analiz sonucu mock'la
        mock_macho_result = StageResult(
            stage_name="static",
            success=True,
            duration_seconds=1.0,
            artifacts={},
            stats={"analyzer": "macho"},
        )

        # symbols.json mock
        symbols_data = {"symbols": sample_symbols}

        # strings_raw mock
        rust_strings_data = {
            "strings": [
                "called `Result::unwrap()` on an `Err` value",
                "panicked at 'test'",
                "Cargo.toml",
                "core::fmt::Display",
            ]
        }

        with patch.object(type(rust_analyzer).__bases__[0], "analyze_static", return_value=mock_macho_result):
            with patch.object(mock_workspace, "load_json") as mock_load:
                def load_side_effect(stage, name):
                    if name == "symbols":
                        return symbols_data
                    if name == "strings_raw":
                        return rust_strings_data
                    return None

                mock_load.side_effect = load_side_effect

                mock_rustfilt = MagicMock()
                mock_rustfilt.success = False
                with patch.object(rust_analyzer.runner, "run_command", return_value=mock_rustfilt):
                    result = rust_analyzer.analyze_static(mock_rust_target, mock_workspace)

        assert isinstance(result, StageResult)
        assert result.success is True
        assert "rust_analysis" in result.stats
        assert result.stats["rust_analysis"].get("demangled_count", 0) > 0
