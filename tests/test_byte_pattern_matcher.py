"""BytePatternMatcher testleri.

FUN_xxx fonksiyonlarini byte pattern ile tanima modulu testleri:
- extract_function_bytes: binary'den byte okuma
- match_unknown_functions: bilinen sigs ile eslestirme
- to_naming_map: sonuclari naming dict'ine cevirme
- index-based hiz optimizasyonu
- edge case'ler: bos input, hatali adres, universal binary
"""

from __future__ import annotations

import json
import struct
import tempfile
import os
from pathlib import Path
from unittest import mock

import pytest

from karadul.analyzers.byte_pattern_matcher import (
    ByteMatchResult,
    BytePatternMatcher,
    MIN_PATTERN_LENGTH,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def matcher():
    """Varsayilan BytePatternMatcher instance'i."""
    return BytePatternMatcher()


@pytest.fixture
def matcher_low_min():
    """Dusuk min_pattern_length ile matcher (test kolayligi icin)."""
    return BytePatternMatcher(min_pattern_length=4, min_confidence=0.50)


@pytest.fixture
def sample_functions_json(tmp_path):
    """Ornek Ghidra functions.json dosyasi."""
    data = {
        "total": 5,
        "program": "test_binary",
        "functions": [
            {"name": "FUN_100001000", "address": "100001000", "size": 128},
            {"name": "FUN_100001080", "address": "100001080", "size": 64},
            {"name": "FUN_100001100", "address": "100001100", "size": 256},
            {"name": "_known_func", "address": "100001200", "size": 32},
            {"name": "FUN_100001300", "address": "100001300", "size": 16},
        ],
    }
    jf = tmp_path / "ghidra_functions.json"
    jf.write_text(json.dumps(data))
    return jf


@pytest.fixture
def sample_functions_json_list(tmp_path):
    """Ghidra functions.json - list formati (dict degil)."""
    data = [
        {"name": "FUN_100001000", "address": "100001000", "size": 128},
        {"name": "FUN_100001080", "address": "100001080", "size": 64},
    ]
    jf = tmp_path / "ghidra_functions_list.json"
    jf.write_text(json.dumps(data))
    return jf


@pytest.fixture
def sample_binary(tmp_path):
    """__TEXT segment vmaddr=0x100000000, fileoff=0 ile sahte binary.

    Fonksiyonlar:
      0x100001000 -> file offset 0x1000: b'\\x55\\x48\\x89\\xe5...' (32 bytes)
      0x100001080 -> file offset 0x1080: b'\\x41\\x57\\x41\\x56...' (32 bytes)
      0x100001100 -> file offset 0x1100: b'\\xf3\\x0f\\x1e\\xfa...' (32 bytes)
      0x100001200 -> file offset 0x1200: zeros
      0x100001300 -> file offset 0x1300: b'\\x55\\x48\\x89\\xe5...' (ayni pattern, baska fonksiyon)
    """
    bin_path = tmp_path / "test_binary"
    # 8KB sahte binary
    data = bytearray(8192)

    # FUN_100001000 (offset 0x1000)
    pattern1 = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec" + \
               b"\xa8\x00\x00\x00\x48\x89\xfb\x4c\x89\xe7\xe8\x00\x00\x00\x00\x90"
    data[0x1000:0x1000 + 32] = pattern1

    # FUN_100001080 (offset 0x1080)
    pattern2 = b"\x41\x57\x41\x56\x41\x55\x41\x54\x55\x53\x48\x83\xec\x38\x48\x89" + \
               b"\xfb\x48\x8b\x07\xff\x50\x18\x48\x89\xc5\x48\x85\xc0\x0f\x84\xab"
    data[0x1080:0x1080 + 32] = pattern2

    # FUN_100001100 (offset 0x1100) -- OpenSSL-like pattern
    pattern3 = b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54" + \
               b"\x53\x48\x83\xec\x28\x48\x89\xfb\x89\xf5\x48\x89\xd7\x4c\x89\xc6"
    data[0x1100:0x1100 + 32] = pattern3

    # FUN_100001300 (offset 0x1300) -- ayni pattern1
    data[0x1300:0x1300 + 32] = pattern1

    bin_path.write_bytes(bytes(data))
    return bin_path, pattern1, pattern2, pattern3


class FakeFLIRTSig:
    """Test icin sahte FLIRT signature."""

    def __init__(
        self,
        name: str = "",
        library: str = "unknown",
        byte_pattern: bytes = b"",
        mask: bytes = b"",
        size_range: tuple[int, int] = (0, 0),
        category: str = "",
        purpose: str = "",
    ):
        self.name = name
        self.library = library
        self.byte_pattern = byte_pattern
        self.mask = mask if mask else b"\xff" * len(byte_pattern)
        self.size_range = size_range
        self.category = category
        self.purpose = purpose


# ---------------------------------------------------------------------------
# ByteMatchResult
# ---------------------------------------------------------------------------

class TestByteMatchResult:
    """ByteMatchResult dataclass testleri."""

    def test_defaults(self):
        r = ByteMatchResult()
        assert r.total_functions == 0
        assert r.total_unknown == 0
        assert r.total_matched == 0
        assert r.matches == {}
        assert r.errors == []
        assert r.duration_seconds == 0.0

    def test_match_rate_zero(self):
        r = ByteMatchResult(total_unknown=0, total_matched=0)
        assert r.match_rate == 0.0

    def test_match_rate_nonzero(self):
        r = ByteMatchResult(total_unknown=100, total_matched=25)
        assert r.match_rate == pytest.approx(0.25)

    def test_match_rate_all(self):
        r = ByteMatchResult(total_unknown=10, total_matched=10)
        assert r.match_rate == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# __TEXT segment parsing
# ---------------------------------------------------------------------------

class TestGetTextSegmentInfo:
    """__TEXT segment info testleri."""

    def test_otool_success(self, matcher, sample_binary):
        """otool ile __TEXT segment bilgisi alinabilir."""
        bin_path, _, _, _ = sample_binary

        # otool mock: tipik Mach-O __TEXT ciktisi
        otool_output = (
            "Load command 1\n"
            "      cmd LC_SEGMENT_64\n"
            "  cmdsize 1912\n"
            "  segname __TEXT\n"
            "   vmaddr 0x0000000100000000\n"
            "   vmsize 0x00000000000b2000\n"
            "  fileoff 0\n"
            " filesize 729088\n"
        )

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                stdout=otool_output, stderr="", returncode=0,
            )
            vmaddr, fileoff, fat_offset = matcher._get_text_segment_info(bin_path)

        assert vmaddr == 0x100000000
        assert fileoff == 0
        assert fat_offset == 0  # normal binary, fat offset yok

    def test_otool_not_found(self, tmp_path):
        """otool yoksa header fallback veya None."""
        m = BytePatternMatcher()
        m._otool_path = None

        bin_path = tmp_path / "nomagic"
        bin_path.write_bytes(b"\x00" * 100)

        vmaddr, fileoff, fat_offset = m._get_text_segment_info(bin_path)
        assert vmaddr is None
        assert fileoff is None
        assert fat_offset == 0

    def test_elf_fallback(self, tmp_path):
        """ELF binary icin heuristik (0, 0)."""
        m = BytePatternMatcher()
        m._otool_path = None

        elf_bin = tmp_path / "elf_binary"
        elf_bin.write_bytes(b"\x7fELF" + b"\x00" * 100)

        vmaddr, fileoff = m._parse_text_segment_header(elf_bin)
        assert vmaddr == 0
        assert fileoff == 0

    def test_pe_fallback(self, tmp_path):
        """PE binary icin heuristik (0, 0)."""
        m = BytePatternMatcher()
        m._otool_path = None

        pe_bin = tmp_path / "pe_binary.exe"
        pe_bin.write_bytes(b"MZ" + b"\x00" * 100)

        vmaddr, fileoff = m._parse_text_segment_header(pe_bin)
        assert vmaddr == 0
        assert fileoff == 0

    def test_fat_binary_offset(self, tmp_path):
        """Universal (fat) binary'nin slice offset'i dogru hesaplanir."""
        m = BytePatternMatcher()

        # Sahte fat binary header olustur (big-endian)
        # Magic: 0xCAFEBABE, nfat=2
        # Arch 1: cputype=7(x86_64), cpusubtype=3, offset=16384, size=100, align=14
        fat_header = struct.pack(">I", 0xCAFEBABE)  # magic
        fat_header += struct.pack(">I", 2)  # nfat
        # Arch 1
        fat_header += struct.pack(">5I", 7, 3, 16384, 100, 14)
        # Arch 2
        fat_header += struct.pack(">5I", 12, 0, 32768, 100, 14)

        fat_bin = tmp_path / "fat_binary"
        fat_bin.write_bytes(fat_header + b"\x00" * 100)

        fat_offset = m._get_fat_offset(fat_bin)
        assert fat_offset == 16384


# ---------------------------------------------------------------------------
# _load_functions
# ---------------------------------------------------------------------------

class TestLoadFunctions:
    """Functions JSON yukleme testleri."""

    def test_dict_format(self, sample_functions_json):
        funcs = BytePatternMatcher._load_functions(sample_functions_json)
        assert funcs is not None
        assert len(funcs) == 5

    def test_list_format(self, sample_functions_json_list):
        funcs = BytePatternMatcher._load_functions(sample_functions_json_list)
        assert funcs is not None
        assert len(funcs) == 2

    def test_nonexistent(self, tmp_path):
        funcs = BytePatternMatcher._load_functions(tmp_path / "nope.json")
        assert funcs is None

    def test_invalid_json(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{invalid")
        funcs = BytePatternMatcher._load_functions(bad)
        assert funcs is None

    def test_empty_functions(self, tmp_path):
        jf = tmp_path / "empty.json"
        jf.write_text(json.dumps({"functions": []}))
        funcs = BytePatternMatcher._load_functions(jf)
        assert funcs == []


# ---------------------------------------------------------------------------
# _read_bytes
# ---------------------------------------------------------------------------

class TestReadBytes:
    """Binary byte okuma testleri."""

    def test_normal_read(self, sample_binary):
        bin_path, pattern1, _, _ = sample_binary
        with open(bin_path, "rb") as f:
            data = BytePatternMatcher._read_bytes(f, 0x1000, 32)
        assert data == pattern1

    def test_read_past_end(self, sample_binary):
        """Dosya sonundan sonra okuma."""
        bin_path, _, _, _ = sample_binary
        with open(bin_path, "rb") as f:
            data = BytePatternMatcher._read_bytes(f, 99999, 32)
        # Dosya sonu gecilirse kisa veya bos donebilir
        assert len(data) < 32


# ---------------------------------------------------------------------------
# _build_sig_index
# ---------------------------------------------------------------------------

class TestBuildSigIndex:
    """Signature index olusturma testleri."""

    def test_fixed_prefix(self):
        """Sabit ilk 4 byte ile index."""
        sigs = [
            FakeFLIRTSig(
                name="_func1",
                byte_pattern=b"\x55\x48\x89\xe5" + b"\x00" * 12,
                mask=b"\xff" * 16,
            ),
        ]
        index = BytePatternMatcher._build_sig_index(sigs)
        key = b"\x55\x48\x89\xe5"
        assert key in index
        assert 0 in index[key]

    def test_wildcard_prefix(self):
        """Ilk 4 byte'ta wildcard olan sig WILD bucket'a gider."""
        sigs = [
            FakeFLIRTSig(
                name="_wild_func",
                byte_pattern=b"\x55\x00\x89\xe5" + b"\x00" * 12,
                mask=b"\xff\x00\xff\xff" + b"\xff" * 12,
            ),
        ]
        index = BytePatternMatcher._build_sig_index(sigs)
        assert b"WILD" in index
        assert 0 in index[b"WILD"]

    def test_short_pattern_excluded(self):
        """4 byte'tan kisa pattern index'e eklenmemeli."""
        sigs = [FakeFLIRTSig(name="_short", byte_pattern=b"\x55\x48")]
        index = BytePatternMatcher._build_sig_index(sigs)
        assert len(index) == 0


# ---------------------------------------------------------------------------
# _match_bytes
# ---------------------------------------------------------------------------

class TestMatchBytes:
    """Tek fonksiyon byte eslestirme testleri."""

    def test_exact_match(self, matcher_low_min):
        """Tam eslestirme -- 16 byte sabit pattern."""
        pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec"
        sigs = [
            FakeFLIRTSig(
                name="_push_rbp_pattern",
                library="libc",
                byte_pattern=pattern,
                mask=b"\xff" * 16,
                category="runtime",
                purpose="function prologue",
            ),
        ]
        index = BytePatternMatcher._build_sig_index(sigs)

        func_bytes = pattern + b"\xa8\x00\x00\x00" * 4  # 32 byte
        result = matcher_low_min._match_bytes(func_bytes, 128, sigs, index)

        assert result is not None
        name, library, conf, category, purpose = result
        assert name == "_push_rbp_pattern"
        assert library == "libc"
        assert conf >= 0.60
        assert category == "runtime"

    def test_no_match(self, matcher_low_min):
        """Eslesmeme durumu."""
        sigs = [
            FakeFLIRTSig(
                name="_other",
                byte_pattern=b"\xAA\xBB\xCC\xDD" + b"\x00" * 12,
                mask=b"\xff" * 16,
            ),
        ]
        index = BytePatternMatcher._build_sig_index(sigs)

        func_bytes = b"\x55\x48\x89\xe5" + b"\x00" * 28
        result = matcher_low_min._match_bytes(func_bytes, 64, sigs, index)
        assert result is None

    def test_wildcard_match(self, matcher_low_min):
        """Wildcard iceren pattern eslesmeli."""
        pattern = b"\x55\x00\x89\xe5" + b"\x41" * 12
        mask = b"\xff\x00\xff\xff" + b"\xff" * 12
        sigs = [
            FakeFLIRTSig(
                name="_wild",
                library="test",
                byte_pattern=pattern,
                mask=mask,
            ),
        ]
        index = BytePatternMatcher._build_sig_index(sigs)

        # Wildcard pozisyonda farkli byte
        func_bytes = b"\x55\xAA\x89\xe5" + b"\x41" * 12 + b"\x00" * 16
        result = matcher_low_min._match_bytes(func_bytes, 64, sigs, index)
        assert result is not None
        assert result[0] == "_wild"

    def test_size_range_filter(self, matcher_low_min):
        """Size range uyumsuzlugu eslestirmeyi engeller."""
        pattern = b"\x55\x48\x89\xe5" + b"\x00" * 12
        sigs = [
            FakeFLIRTSig(
                name="_sized",
                byte_pattern=pattern,
                mask=b"\xff" * 16,
                size_range=(200, 500),  # 200-500 byte
            ),
        ]
        index = BytePatternMatcher._build_sig_index(sigs)

        # func_size=64 -> range disinda
        func_bytes = pattern + b"\x00" * 16
        result = matcher_low_min._match_bytes(func_bytes, 64, sigs, index)
        assert result is None

        # func_size=300 -> range icinde
        result = matcher_low_min._match_bytes(func_bytes, 300, sigs, index)
        assert result is not None

    def test_too_short_func_bytes(self, matcher):
        """Min pattern length'ten kisa func_bytes eslesmemeli."""
        sigs = [
            FakeFLIRTSig(
                name="_test",
                byte_pattern=b"\x55" * 20,
                mask=b"\xff" * 20,
            ),
        ]
        index = BytePatternMatcher._build_sig_index(sigs)

        result = matcher._match_bytes(b"\x55" * 10, 64, sigs, index)
        assert result is None

    def test_best_match_by_confidence(self, matcher_low_min):
        """Birden fazla eslestirme varsa en yuksek confidence secilmeli."""
        short_pattern = b"\x55\x48\x89\xe5" + b"\x00" * 12  # 16 byte
        long_pattern = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xec" + \
                       b"\xa8\x00\x00\x00\x48\x89\xfb\x4c"  # 24 byte

        sigs = [
            FakeFLIRTSig(name="_short", library="lib1", byte_pattern=short_pattern, mask=b"\xff" * 16),
            FakeFLIRTSig(name="_long", library="lib2", byte_pattern=long_pattern, mask=b"\xff" * 24),
        ]
        index = BytePatternMatcher._build_sig_index(sigs)

        func_bytes = long_pattern + b"\x00" * 8  # 32 byte, iki pattern de eslesir
        result = matcher_low_min._match_bytes(func_bytes, 128, sigs, index)
        assert result is not None
        # Uzun pattern daha yuksek confidence -> _long secilmeli
        assert result[0] == "_long"


# ---------------------------------------------------------------------------
# match_unknown_functions (entegrasyon)
# ---------------------------------------------------------------------------

class TestMatchUnknownFunctions:
    """match_unknown_functions entegrasyon testleri."""

    def test_nonexistent_binary(self, matcher, tmp_path):
        """Binary yok -> errors."""
        jf = tmp_path / "funcs.json"
        jf.write_text(json.dumps({"functions": []}))

        result = matcher.match_unknown_functions(
            "/nonexistent/binary",
            jf,
            [],
        )
        assert result.total_matched == 0
        assert any("bulunamadi" in e for e in result.errors)

    def test_nonexistent_functions_json(self, matcher, sample_binary):
        """Functions JSON yok -> errors."""
        bin_path, _, _, _ = sample_binary
        result = matcher.match_unknown_functions(
            bin_path,
            "/nonexistent/funcs.json",
            [],
        )
        assert result.total_matched == 0
        assert any("bulunamadi" in e for e in result.errors)

    def test_no_byte_sigs(self, matcher, sample_binary, sample_functions_json):
        """Yeterli byte pattern yok -> bos sonuc."""
        bin_path, _, _, _ = sample_binary
        result = matcher.match_unknown_functions(
            bin_path,
            sample_functions_json,
            [],  # bos signature listesi
        )
        assert result.total_matched == 0
        assert result.errors == []

    def test_successful_match(self, sample_binary, sample_functions_json):
        """Binary'den byte okuyup signature ile eslestirme."""
        bin_path, pattern1, _, _ = sample_binary

        # pattern1 ile eslesen signature
        sig = FakeFLIRTSig(
            name="_known_prologue",
            library="libc",
            byte_pattern=pattern1[:20],  # ilk 20 byte
            mask=b"\xff" * 20,
            category="runtime",
            purpose="standard prologue",
        )

        m = BytePatternMatcher(min_pattern_length=16, min_confidence=0.50)

        # otool mock
        otool_output = (
            "  segname __TEXT\n"
            "   vmaddr 0x0000000100000000\n"
            "  fileoff 0\n"
        )
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                stdout=otool_output, stderr="", returncode=0,
            )
            result = m.match_unknown_functions(
                bin_path,
                sample_functions_json,
                [sig],
            )

        # FUN_100001000 ve FUN_100001300 ayni pattern1'e sahip
        assert result.total_functions == 5
        assert result.total_unknown == 4  # 4 FUN_xxx
        assert result.total_matched >= 2  # en az 2 eslestirme (pattern1 ile)
        assert "FUN_100001000" in result.matches
        assert "FUN_100001300" in result.matches
        assert result.matches["FUN_100001000"]["matched_name"] == "_known_prologue"
        assert result.duration_seconds > 0

    def test_list_format_json(self, sample_binary, sample_functions_json_list):
        """List formatindaki functions.json de calisir."""
        bin_path, pattern1, _, _ = sample_binary

        sig = FakeFLIRTSig(
            name="_func",
            library="lib",
            byte_pattern=pattern1[:16],
            mask=b"\xff" * 16,
        )

        m = BytePatternMatcher(min_pattern_length=16, min_confidence=0.50)

        otool_output = "  segname __TEXT\n   vmaddr 0x0000000100000000\n  fileoff 0\n"
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(stdout=otool_output, stderr="", returncode=0)
            result = m.match_unknown_functions(bin_path, sample_functions_json_list, [sig])

        assert result.total_unknown == 2
        assert result.total_matched >= 1


# ---------------------------------------------------------------------------
# extract_function_bytes
# ---------------------------------------------------------------------------

class TestExtractFunctionBytes:
    """extract_function_bytes testleri."""

    def test_extract_all(self, sample_binary, sample_functions_json):
        """Tum fonksiyonlarin byte'lari cikarilir."""
        bin_path, pattern1, pattern2, pattern3 = sample_binary

        m = BytePatternMatcher()

        otool_output = "  segname __TEXT\n   vmaddr 0x0000000100000000\n  fileoff 0\n"
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(stdout=otool_output, stderr="", returncode=0)
            func_bytes = m.extract_function_bytes(bin_path, sample_functions_json)

        assert "FUN_100001000" in func_bytes
        assert func_bytes["FUN_100001000"] == pattern1
        assert "FUN_100001080" in func_bytes
        assert func_bytes["FUN_100001080"] == pattern2
        assert "_known_func" in func_bytes  # bilinen fonksiyon da cikarilir

    def test_nonexistent_binary(self, matcher, sample_functions_json):
        result = matcher.extract_function_bytes("/nonexistent/bin", sample_functions_json)
        assert result == {}

    def test_nonexistent_json(self, matcher, sample_binary):
        bin_path, _, _, _ = sample_binary
        result = matcher.extract_function_bytes(bin_path, "/nonexistent/funcs.json")
        assert result == {}


# ---------------------------------------------------------------------------
# to_naming_map
# ---------------------------------------------------------------------------

class TestToNamingMap:
    """to_naming_map testleri."""

    def test_basic_mapping(self):
        """Temel isim donusumu."""
        result = ByteMatchResult(
            matches={
                "FUN_100001000": {
                    "matched_name": "_SSL_CTX_new",
                    "library": "openssl",
                    "confidence": 0.85,
                    "category": "crypto",
                    "purpose": "SSL context",
                },
                "FUN_100001080": {
                    "matched_name": "_deflate",
                    "library": "zlib",
                    "confidence": 0.80,
                    "category": "compression",
                    "purpose": "zlib compress",
                },
            },
        )
        naming_map = BytePatternMatcher.to_naming_map(result)
        assert naming_map["FUN_100001000"] == "SSL_CTX_new"  # _ prefix kaldirilmis
        assert naming_map["FUN_100001080"] == "deflate"

    def test_no_leading_underscore(self):
        """_ prefix olmayan isim oldugu gibi kalir."""
        result = ByteMatchResult(
            matches={
                "FUN_100001000": {
                    "matched_name": "some_function",
                    "library": "lib",
                    "confidence": 0.80,
                    "category": "",
                    "purpose": "",
                },
            },
        )
        naming_map = BytePatternMatcher.to_naming_map(result)
        assert naming_map["FUN_100001000"] == "some_function"

    def test_empty_matched_name_skipped(self):
        """Bos matched_name atlanmali."""
        result = ByteMatchResult(
            matches={
                "FUN_100001000": {
                    "matched_name": "",
                    "library": "lib",
                    "confidence": 0.80,
                    "category": "",
                    "purpose": "",
                },
            },
        )
        naming_map = BytePatternMatcher.to_naming_map(result)
        assert "FUN_100001000" not in naming_map

    def test_empty_matches(self):
        """Bos matches -> bos dict."""
        result = ByteMatchResult()
        naming_map = BytePatternMatcher.to_naming_map(result)
        assert naming_map == {}


# ---------------------------------------------------------------------------
# MIN_PATTERN_LENGTH sabiti
# ---------------------------------------------------------------------------

class TestMinPatternLength:
    """MIN_PATTERN_LENGTH sabiti testleri."""

    def test_default_value(self):
        """Varsayilan min pattern 16 byte."""
        assert MIN_PATTERN_LENGTH == 16

    def test_matcher_enforces_min(self):
        """Matcher 8'den kucuk min pattern kabul etmemeli."""
        m = BytePatternMatcher(min_pattern_length=2)
        assert m._min_pattern_length == 8  # max(2, 8) = 8

    def test_matcher_default(self):
        """Varsayilan matcher 16 byte min kullanir."""
        m = BytePatternMatcher()
        assert m._min_pattern_length == 16


# ---------------------------------------------------------------------------
# GHIDRA_AUTO_NAME_RE
# ---------------------------------------------------------------------------

class TestGhidraAutoNameRegex:
    """Ghidra auto-name regex testleri."""

    def test_fun_xxx(self):
        from karadul.analyzers.byte_pattern_matcher import _GHIDRA_AUTO_NAME_RE
        assert _GHIDRA_AUTO_NAME_RE.match("FUN_1000019c0")
        assert _GHIDRA_AUTO_NAME_RE.match("FUN_100001e40")

    def test_thunk_fun(self):
        from karadul.analyzers.byte_pattern_matcher import _GHIDRA_AUTO_NAME_RE
        assert _GHIDRA_AUTO_NAME_RE.match("thunk_FUN_100001e40")

    def test_switch_fun(self):
        from karadul.analyzers.byte_pattern_matcher import _GHIDRA_AUTO_NAME_RE
        assert _GHIDRA_AUTO_NAME_RE.match("switch_FUN_100001e40")

    def test_known_name_no_match(self):
        from karadul.analyzers.byte_pattern_matcher import _GHIDRA_AUTO_NAME_RE
        assert not _GHIDRA_AUTO_NAME_RE.match("_SSL_CTX_new")
        assert not _GHIDRA_AUTO_NAME_RE.match("_deflate")
        assert not _GHIDRA_AUTO_NAME_RE.match("main")


# ---------------------------------------------------------------------------
# Config entegrasyonu
# ---------------------------------------------------------------------------

class TestConfigIntegration:
    """BinaryReconstructionConfig.enable_byte_pattern_matching testi."""

    def test_config_flag_exists(self):
        from karadul.config import BinaryReconstructionConfig
        cfg = BinaryReconstructionConfig()
        assert hasattr(cfg, "enable_byte_pattern_matching")
        assert cfg.enable_byte_pattern_matching is True

    def test_config_flag_disabled(self):
        from karadul.config import BinaryReconstructionConfig
        cfg = BinaryReconstructionConfig(enable_byte_pattern_matching=False)
        assert cfg.enable_byte_pattern_matching is False
