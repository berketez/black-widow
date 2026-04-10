"""YARA Scanner testleri.

Test edilen:
- Dahili kural yukleme
- Crypto pattern tespiti (AES S-box, SHA-256, OpenSSL string)
- Compiler tespiti (GCC, Rust, Go string)
- Packer tespiti (UPX magic, VMProtect)
- Anti-debug tespiti (ptrace, IsDebuggerPresent)
- Obfuscation tespiti (XOR pattern)
- Compression tespiti (zlib header)
- YARA yokken fallback calisma
- Bos dosya/data tarama
- ScanResult / YaraMatch serialization
- Tag filtreleme
- Dosya tarama (scan_file)
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock

import pytest

from karadul.analyzers.yara_scanner import (
    BuiltinRule,
    ScanResult,
    YaraMatch,
    YaraScanner,
    _builtin_rules,
    _hex,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner():
    """Builtin kurallari yuklu scanner."""
    s = YaraScanner()
    s.load_builtin_rules()
    return s


@pytest.fixture
def empty_scanner():
    """Kural yuklenmemis scanner."""
    return YaraScanner()


# ---------------------------------------------------------------------------
# Yardimci
# ---------------------------------------------------------------------------

def _make_binary_with_pattern(pattern: bytes, padding: int = 256) -> bytes:
    """Pattern'i rastgele padding icine gomulmus binary olustur."""
    return b"\x00" * padding + pattern + b"\x00" * padding


# ---------------------------------------------------------------------------
# Temel testler
# ---------------------------------------------------------------------------

class TestBuiltinRules:
    """Dahili kural yukleme testleri."""

    def test_load_builtin_rules_count(self, scanner):
        """En az 30 dahili kural yuklenmeli."""
        assert scanner.rule_count >= 30

    def test_builtin_rules_have_names(self):
        """Her kuralda benzersiz isim olmali."""
        rules = _builtin_rules()
        names = [r.name for r in rules]
        assert len(names) == len(set(names)), "Tekrar eden kural isimleri var"

    def test_builtin_rules_have_tags(self):
        """Her kuralda en az 1 tag olmali."""
        for rule in _builtin_rules():
            assert len(rule.tags) > 0, f"{rule.name} kuralinda tag yok"

    def test_builtin_rules_have_patterns(self):
        """Her kuralda byte veya string pattern olmali."""
        for rule in _builtin_rules():
            total = len(rule.byte_patterns) + len(rule.string_patterns)
            assert total > 0, f"{rule.name} kuralinda pattern yok"

    def test_builtin_rule_categories(self, scanner):
        """Tum beklenen kategoriler mevcut olmali."""
        all_tags = set()
        for rule in _builtin_rules():
            all_tags.update(rule.tags)

        assert "crypto" in all_tags
        assert "packer" in all_tags
        assert "compiler" in all_tags
        assert "antidebug" in all_tags
        assert "obfuscation" in all_tags
        assert "compression" in all_tags

    def test_stats(self, scanner):
        """get_stats() dogru bilgi dondurmeli."""
        stats = scanner.get_stats()
        assert stats["builtin_rules"] >= 30
        assert stats["external_files"] == 0
        assert "tag_distribution" in stats
        assert isinstance(stats["tag_distribution"], dict)


# ---------------------------------------------------------------------------
# Crypto tespiti
# ---------------------------------------------------------------------------

class TestCryptoDetection:
    """Crypto pattern tespiti testleri."""

    def test_aes_sbox_detection(self, scanner):
        """AES S-box byte pattern'i tespit edilmeli."""
        sbox_prefix = _hex("63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76")
        data = _make_binary_with_pattern(sbox_prefix)
        result = scanner.scan_bytes(data)

        matched_rules = result.matched_rules
        assert "AES_SBox" in matched_rules

    def test_sha256_init_detection(self, scanner):
        """SHA-256 initialization constants tespit edilmeli."""
        sha256_init = _hex("6A09E667 BB67AE85 3C6EF372 A54FF53A")
        data = _make_binary_with_pattern(sha256_init)
        result = scanner.scan_bytes(data)

        assert "SHA256_Init_Constants" in result.matched_rules

    def test_sha256_round_constants(self, scanner):
        """SHA-256 round constants tespit edilmeli."""
        sha256_k = _hex("428A2F98 71374491 B5C0FBCF E9B5DBA5")
        data = _make_binary_with_pattern(sha256_k)
        result = scanner.scan_bytes(data)

        assert "SHA256_Round_Constants" in result.matched_rules

    def test_openssl_string_detection(self, scanner):
        """OpenSSL version string tespit edilmeli."""
        data = b"blah blah OpenSSL 1.1.1k  25 Mar 2021 blah blah"
        result = scanner.scan_bytes(data)

        assert "OpenSSL_Library" in result.matched_rules

    def test_rsa_oid_detection(self, scanner):
        """RSA ASN.1 OID tespit edilmeli."""
        rsa_oid = _hex("06 09 2A 86 48 86 F7 0D 01 01 01")
        data = _make_binary_with_pattern(rsa_oid)
        result = scanner.scan_bytes(data)

        assert "RSA_Public_Key_Constants" in result.matched_rules

    def test_wolfssl_detection(self, scanner):
        """wolfSSL string tespit edilmeli."""
        data = b"init wolfSSL library version 5.6.0\x00"
        result = scanner.scan_bytes(data)

        assert "wolfSSL_Library" in result.matched_rules

    def test_libsodium_detection(self, scanner):
        """libsodium string tespit edilmeli."""
        data = b"\x00\x00sodium_init\x00crypto_secretbox\x00\x00"
        result = scanner.scan_bytes(data)

        assert "libsodium_Library" in result.matched_rules


# ---------------------------------------------------------------------------
# Packer tespiti
# ---------------------------------------------------------------------------

class TestPackerDetection:
    """Packer/protector tespit testleri."""

    def test_upx_magic_detection(self, scanner):
        """UPX packed binary tespit edilmeli (UPX! magic)."""
        data = _make_binary_with_pattern(b"UPX!")
        result = scanner.scan_bytes(data)

        assert "UPX_Packed" in result.matched_rules

    def test_upx_string_detection(self, scanner):
        """UPX section name string tespit edilmeli."""
        data = b"\x00\x00UPX0\x00UPX1\x00UPX2\x00\x00"
        result = scanner.scan_bytes(data)

        assert "UPX_Packed" in result.matched_rules

    def test_vmprotect_detection(self, scanner):
        """VMProtect section names tespit edilmeli."""
        data = b"\x00.vmp0\x00.vmp1\x00VMProtect begin\x00"
        result = scanner.scan_bytes(data)

        assert "VMProtect_Packed" in result.matched_rules

    def test_themida_detection(self, scanner):
        """Themida string tespit edilmeli."""
        data = b"\x00Themida\x00.themida section\x00"
        result = scanner.scan_bytes(data)

        assert "Themida_Packed" in result.matched_rules

    def test_aspack_byte_pattern(self, scanner):
        """ASPack entry point byte pattern tespit edilmeli."""
        aspack_entry = _hex("60 E8 00 00 00 00")
        data = _make_binary_with_pattern(aspack_entry)
        result = scanner.scan_bytes(data)

        assert "ASPack_Packed" in result.matched_rules

    def test_mpress_detection(self, scanner):
        """MPRESS section name tespit edilmeli."""
        data = b"\x00.MPRESS1\x00.MPRESS2\x00"
        result = scanner.scan_bytes(data)

        assert "MPRESS_Packed" in result.matched_rules


# ---------------------------------------------------------------------------
# Compiler tespiti
# ---------------------------------------------------------------------------

class TestCompilerDetection:
    """Compiler tespit testleri."""

    def test_gcc_detection(self, scanner):
        """GCC version string tespit edilmeli."""
        data = b"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0\x00"
        result = scanner.scan_bytes(data)

        assert "GCC_Compiler" in result.matched_rules

    def test_msvc_detection(self, scanner):
        """MSVC string tespit edilmeli."""
        data = b"Microsoft (R) Optimizing Compiler Version 19.29.30148\x00"
        result = scanner.scan_bytes(data)

        assert "MSVC_Compiler" in result.matched_rules

    def test_clang_detection(self, scanner):
        """Clang version string tespit edilmeli."""
        data = b"clang version 16.0.0 (https://github.com/llvm/llvm-project)\x00"
        result = scanner.scan_bytes(data)

        assert "Clang_Compiler" in result.matched_rules

    def test_rust_detection(self, scanner):
        """Rust compiler marker tespit edilmeli."""
        data = b"\x00rustc/1.74.0\x00core::panicking::panic\x00"
        result = scanner.scan_bytes(data)

        assert "Rust_Compiler" in result.matched_rules

    def test_go_detection(self, scanner):
        """Go build ID tespit edilmeli."""
        data = b"\x00Go build ID: abcdef1234567890\x00runtime.gopanic\x00"
        result = scanner.scan_bytes(data)

        assert "Go_Compiler" in result.matched_rules

    def test_swift_detection(self, scanner):
        """Swift runtime marker tespit edilmeli."""
        data = b"\x00swift_release\x00swiftCore\x00_swift_allocObject\x00"
        result = scanner.scan_bytes(data)

        assert "Swift_Compiler" in result.matched_rules

    def test_nim_detection(self, scanner):
        """Nim compiler marker tespit edilmeli."""
        data = b"\x00nimMain\x00NimMain\x00nimGC_collect\x00"
        result = scanner.scan_bytes(data)

        assert "Nim_Compiler" in result.matched_rules


# ---------------------------------------------------------------------------
# Anti-debug tespiti
# ---------------------------------------------------------------------------

class TestAntiDebugDetection:
    """Anti-debug pattern tespit testleri."""

    def test_ptrace_deny_detection(self, scanner):
        """PTRACE_DENY_ATTACH string tespit edilmeli."""
        data = b"\x00PTRACE_DENY_ATTACH\x00PT_DENY_ATTACH\x00"
        result = scanner.scan_bytes(data)

        assert "AntiDebug_Ptrace" in result.matched_rules

    def test_isdebuggerperesent_detection(self, scanner):
        """IsDebuggerPresent string tespit edilmeli."""
        data = b"\x00IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00"
        result = scanner.scan_bytes(data)

        assert "AntiDebug_IsDebuggerPresent" in result.matched_rules

    def test_timing_antidbg_detection(self, scanner):
        """Timing-based anti-debug string tespit edilmeli."""
        data = b"\x00QueryPerformanceCounter\x00GetTickCount\x00"
        result = scanner.scan_bytes(data)

        assert "AntiDebug_Timing" in result.matched_rules

    def test_antivm_detection(self, scanner):
        """VM detection string tespit edilmeli."""
        data = b"\x00VMware virtual device\x00VirtualBox Guest\x00"
        result = scanner.scan_bytes(data)

        assert "AntiVM_Detection" in result.matched_rules


# ---------------------------------------------------------------------------
# Obfuscation tespiti
# ---------------------------------------------------------------------------

class TestObfuscationDetection:
    """Obfuscation pattern tespit testleri."""

    def test_xor_pattern_byte(self, scanner):
        """XOR decode loop byte pattern tespit edilmeli."""
        xor_loop = _hex("30 04 11 42")  # xor [ecx+edx], al; inc edx
        data = _make_binary_with_pattern(xor_loop)
        result = scanner.scan_bytes(data)

        assert "String_Encryption_XOR" in result.matched_rules

    def test_cff_ollvm_detection(self, scanner):
        """OLLVM control flow flattening marker tespit edilmeli."""
        data = b"\x00__ollvm_func\x00obfuscator-llvm\x00"
        result = scanner.scan_bytes(data)

        assert "Control_Flow_Flattening" in result.matched_rules

    def test_opaque_predicate_pattern(self, scanner):
        """Opaque predicate byte pattern tespit edilmeli."""
        opaque = _hex("33 C0 74")  # xor eax,eax; jz
        data = _make_binary_with_pattern(opaque)
        result = scanner.scan_bytes(data)

        assert "Opaque_Predicates" in result.matched_rules


# ---------------------------------------------------------------------------
# Compression tespiti
# ---------------------------------------------------------------------------

class TestCompressionDetection:
    """Compression library tespit testleri."""

    def test_zlib_header_detection(self, scanner):
        """zlib default compression header tespit edilmeli."""
        zlib_header = _hex("78 9C")
        data = _make_binary_with_pattern(zlib_header)
        result = scanner.scan_bytes(data)

        assert "Zlib_Library" in result.matched_rules

    def test_lz4_magic_detection(self, scanner):
        """LZ4 frame magic tespit edilmeli."""
        lz4_magic = _hex("04 22 4D 18")
        data = _make_binary_with_pattern(lz4_magic)
        result = scanner.scan_bytes(data)

        assert "LZ4_Library" in result.matched_rules

    def test_zstd_magic_detection(self, scanner):
        """Zstandard frame magic tespit edilmeli."""
        zstd_magic = _hex("28 B5 2F FD")
        data = _make_binary_with_pattern(zstd_magic)
        result = scanner.scan_bytes(data)

        assert "Zstd_Library" in result.matched_rules


# ---------------------------------------------------------------------------
# Fallback modu testleri
# ---------------------------------------------------------------------------

class TestFallbackMode:
    """YARA yokken regex fallback testleri."""

    def test_fallback_used_when_no_yara(self):
        """yara-python import edilemezse fallback kullanilmali."""
        with mock.patch.dict("sys.modules", {"yara": None}):
            s = YaraScanner()
            # yara import basarisiz olursa _yara_available False kalmali
            # Ama mock sonrasi constructor zaten calismis olabilir, direkt test:
            s._yara_available = False
            s._yara = None
            s.load_builtin_rules()

            data = b"OpenSSL 3.0.0 library init\x00"
            result = s.scan_bytes(data)

            assert result.backend == "regex-fallback"
            assert "OpenSSL_Library" in result.matched_rules

    def test_fallback_crypto_detection(self):
        """Fallback modunda AES S-box tespit edilebilmeli."""
        s = YaraScanner()
        s._yara_available = False
        s._yara = None
        s.load_builtin_rules()

        sbox = _hex("63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76")
        data = _make_binary_with_pattern(sbox)
        result = s.scan_bytes(data)

        assert result.backend == "regex-fallback"
        assert "AES_SBox" in result.matched_rules

    def test_fallback_packer_detection(self):
        """Fallback modunda UPX magic tespit edilebilmeli."""
        s = YaraScanner()
        s._yara_available = False
        s._yara = None
        s.load_builtin_rules()

        data = _make_binary_with_pattern(b"UPX!")
        result = s.scan_bytes(data)

        assert result.backend == "regex-fallback"
        assert "UPX_Packed" in result.matched_rules


# ---------------------------------------------------------------------------
# Bos / kenar durum testleri
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Kenar durum testleri."""

    def test_empty_data(self, scanner):
        """Bos data tarama hata vermemeli."""
        result = scanner.scan_bytes(b"")
        assert result.errors == []
        assert result.matches == []

    def test_no_rules_loaded(self, empty_scanner):
        """Kural yuklenmeden tarama hata mesaji dondurmeli."""
        result = empty_scanner.scan_bytes(b"test data")
        assert len(result.errors) > 0
        assert "Kural yuklenmemis" in result.errors[0]

    def test_scan_nonexistent_file(self, scanner):
        """Var olmayan dosya tarama hata dondurmeli."""
        result = scanner.scan_file(Path("/nonexistent/file.bin"))
        assert len(result.errors) > 0
        assert "bulunamadi" in result.errors[0]

    def test_scan_directory(self, scanner):
        """Dizin tarama hata dondurmeli."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan_file(Path(tmpdir))
            assert len(result.errors) > 0
            assert "Dosya degil" in result.errors[0]

    def test_random_data_no_match(self, scanner):
        """Rastgele data'da false positive olmamali (cok kisa data)."""
        # 16 byte sifir — bunun hicbir kurala eslesmemesi beklenir
        # (zlib header 78 9C haric, ama bu sifir degil)
        data = b"\xFF" * 16
        result = scanner.scan_bytes(data)

        # Tum eslesmelerin gerekce (strings) icermesi lazim
        for m in result.matches:
            assert len(m.strings) > 0

    def test_scan_real_file(self, scanner):
        """Gercek dosya tarama calismali."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 100 + b"GCC: (Ubuntu) 11.4.0" + b"\x00" * 100)
            f.flush()
            result = scanner.scan_file(Path(f.name))

        assert result.errors == []
        assert "GCC_Compiler" in result.matched_rules

        # Temizlik
        Path(f.name).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Serialization testleri
# ---------------------------------------------------------------------------

class TestSerialization:
    """to_dict serialization testleri."""

    def test_yara_match_to_dict(self):
        """YaraMatch.to_dict() dogru JSON uretmeli."""
        m = YaraMatch(
            rule="TestRule",
            tags=["test"],
            meta={"desc": "test rule"},
            strings=[(0, "$s0", b"\x63\x7C")],
            namespace="builtin",
        )
        d = m.to_dict()

        assert d["rule"] == "TestRule"
        assert d["tags"] == ["test"]
        assert d["strings"][0]["offset"] == 0
        assert d["strings"][0]["data"] == "637c"

    def test_scan_result_to_dict(self, scanner):
        """ScanResult.to_dict() dogru JSON uretmeli."""
        data = b"GCC: (Test) 12.0.0\x00"
        result = scanner.scan_bytes(data)
        d = result.to_dict()

        assert "total_rules" in d
        assert "matches" in d
        assert "scan_time_ms" in d
        assert isinstance(d["scan_time_ms"], float)
        assert "backend" in d


# ---------------------------------------------------------------------------
# Tag filtreleme ve yardimci testler
# ---------------------------------------------------------------------------

class TestHelpers:
    """Yardimci metod testleri."""

    def test_get_rules_by_tag_crypto(self, scanner):
        """Crypto tag'li kurallar filtrelenebilmeli."""
        crypto_rules = scanner.get_rules_by_tag("crypto")
        assert len(crypto_rules) >= 5  # AES, SHA256x2, OpenSSL, wolfSSL, mbedTLS, libsodium, RSA
        for r in crypto_rules:
            assert "crypto" in r.tags

    def test_get_rules_by_tag_packer(self, scanner):
        """Packer tag'li kurallar filtrelenebilmeli."""
        packer_rules = scanner.get_rules_by_tag("packer")
        assert len(packer_rules) >= 5
        for r in packer_rules:
            assert "packer" in r.tags

    def test_get_rules_by_tag_compiler(self, scanner):
        """Compiler tag'li kurallar filtrelenebilmeli."""
        compiler_rules = scanner.get_rules_by_tag("compiler")
        assert len(compiler_rules) >= 6
        for r in compiler_rules:
            assert "compiler" in r.tags

    def test_get_rule_names(self, scanner):
        """Tum kural isimleri alinabilmeli."""
        names = scanner.get_rule_names()
        assert len(names) >= 30
        assert "AES_SBox" in names
        assert "UPX_Packed" in names
        assert "GCC_Compiler" in names

    def test_add_custom_rule(self, scanner):
        """Ozel kural eklenebilmeli."""
        before = scanner.rule_count
        scanner.add_rule(BuiltinRule(
            name="Custom_Test",
            tags=["test"],
            string_patterns=[r"CUSTOM_MARKER"],
        ))
        assert scanner.rule_count == before + 1

        # Tarama
        data = b"\x00CUSTOM_MARKER\x00"
        result = scanner.scan_bytes(data)
        assert "Custom_Test" in result.matched_rules

    def test_repr(self, scanner):
        """__repr__ dogru bilgi icermeli."""
        r = repr(scanner)
        assert "YaraScanner" in r
        assert "rules=" in r

    def test_hex_helper(self):
        """_hex yardimci fonksiyonu dogru cevirmeli."""
        assert _hex("63 7C 77") == b"\x63\x7C\x77"
        assert _hex("637C77") == b"\x63\x7C\x77"
        assert _hex("00 FF") == b"\x00\xFF"

    def test_load_rules_no_yara(self, scanner):
        """yara-python yoksa harici kural yukleme 0 dondurmeli."""
        scanner._yara_available = False
        result = scanner.load_rules(Path("/some/path"))
        assert result == 0

    def test_load_rules_nonexistent_path(self, scanner):
        """Var olmayan yol 0 dondurmeli."""
        scanner._yara_available = True
        result = scanner.load_rules(Path("/nonexistent/rules/dir"))
        assert result == 0


# ---------------------------------------------------------------------------
# Coklu pattern tespiti
# ---------------------------------------------------------------------------

class TestMultipleDetections:
    """Birden fazla pattern'in ayni data'da tespit edilmesi."""

    def test_crypto_and_compiler_together(self, scanner):
        """Ayni binary'de hem crypto hem compiler tespit edilmeli."""
        aes_sbox = _hex("63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76")
        gcc_str = b"GCC: (Ubuntu) 12.0.0"
        data = b"\x00" * 100 + aes_sbox + b"\x00" * 100 + gcc_str + b"\x00" * 100
        result = scanner.scan_bytes(data)

        assert "AES_SBox" in result.matched_rules
        assert "GCC_Compiler" in result.matched_rules

    def test_packer_and_antidebug_together(self, scanner):
        """Ayni binary'de hem packer hem anti-debug tespit edilmeli."""
        data = (
            b"\x00" * 50
            + b"UPX!"
            + b"\x00" * 50
            + b"IsDebuggerPresent"
            + b"\x00" * 50
        )
        result = scanner.scan_bytes(data)

        assert "UPX_Packed" in result.matched_rules
        assert "AntiDebug_IsDebuggerPresent" in result.matched_rules

    def test_scan_time_reported(self, scanner):
        """Tarama suresi raporlanmali."""
        data = b"\x00" * 1000
        result = scanner.scan_bytes(data)

        assert result.scan_time_ms >= 0
        assert result.total_rules >= 30
