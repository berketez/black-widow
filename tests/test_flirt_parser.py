"""FLIRT parser ve SignatureDB entegrasyonu testleri.

Test edilen:
- .pat satir parsing
- Wildcard byte handling (_hex_to_bytes_with_mask)
- nm extraction (mock)
- JSON signature yukleme
- SignatureDB injection + duplikasyon kontrolu
- match_function_bytes dogrulugu
- Dizin tarama
- export_to_json
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from karadul.analyzers.flirt_parser import FLIRTParser, FLIRTSignature


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Baslangic FLIRTParser instance'i."""
    return FLIRTParser()


@pytest.fixture
def sample_pat_content():
    """Ornek .pat dosya icerigi."""
    return """\
# IDA FLIRT pattern file -- test
# library: test_lib
558BEC83EC10 0C 0025 003A :0000 _my_function
558BEC........8B4508 00 0000 001F :0000 _another_func
4883EC28488D..........E8........4889C7 AB 0100 0200 :0000 _complex_func
---
# End of file
"""


@pytest.fixture
def sample_json_content():
    """Ornek JSON signature icerigi."""
    return {
        "meta": {"generator": "test", "version": "1.0"},
        "signatures": [
            {
                "name": "_SSL_CTX_new",
                "library": "openssl",
                "category": "crypto",
                "purpose": "SSL context creation",
                "confidence": 0.85,
            },
            {
                "name": "_EVP_EncryptInit_ex",
                "library": "openssl",
                "category": "crypto",
                "purpose": "AES encryption init",
                "confidence": 0.90,
                "size": 256,
            },
            {
                "name": "_deflate",
                "library": "zlib",
                "category": "compression",
                "purpose": "zlib compression",
                "confidence": 0.85,
                "byte_pattern": "558BEC83EC10",
            },
        ],
        "total": 3,
    }


@pytest.fixture
def pat_file(tmp_path, sample_pat_content):
    """Gecici .pat dosyasi."""
    pat = tmp_path / "test_lib.pat"
    pat.write_text(sample_pat_content)
    return pat


@pytest.fixture
def json_file(tmp_path, sample_json_content):
    """Gecici JSON dosyasi."""
    jf = tmp_path / "test_sigs.json"
    jf.write_text(json.dumps(sample_json_content))
    return jf


# ---------------------------------------------------------------------------
# .pat satir parsing
# ---------------------------------------------------------------------------

class TestPatLineParsing:
    """PAT satir parsing testleri."""

    def test_simple_pat_line(self, parser):
        """Basit .pat satiri dogru parse edilir."""
        line = "558BEC83EC10 0C 0025 003A :0000 _my_function"
        sig = parser._parse_pat_line(line, "testlib")

        assert sig is not None
        assert sig.name == "_my_function"
        assert sig.library == "testlib"
        assert sig.crc16 == 0x0C
        assert sig.size == 0x0025
        assert sig.offset == 0x0000
        assert sig.confidence == 0.95
        assert len(sig.byte_pattern) == 6
        assert len(sig.mask) == 6
        # Tum byte'lar sabit (wildcard yok)
        assert sig.mask == b"\xff\xff\xff\xff\xff\xff"

    def test_wildcard_pat_line(self, parser):
        """Wildcard iceren .pat satiri dogru parse edilir."""
        line = "558BEC........8B4508 00 0000 001F :0000 _another_func"
        sig = parser._parse_pat_line(line, "testlib")

        assert sig is not None
        assert sig.name == "_another_func"
        # 558BEC = 3 byte, ........ = 4 wildcard byte (8 dots / 2), 8B4508 = 3 byte
        assert len(sig.byte_pattern) == 10
        assert len(sig.mask) == 10
        # Wildcard pozisyonlari
        assert sig.mask[0] == 0xFF  # 55
        assert sig.mask[1] == 0xFF  # 8B
        assert sig.mask[2] == 0xFF  # EC
        assert sig.mask[3] == 0x00  # ..
        assert sig.mask[4] == 0x00  # ..
        assert sig.mask[5] == 0x00  # ..
        assert sig.mask[6] == 0x00  # ..
        assert sig.mask[7] == 0xFF  # 8B
        assert sig.mask[8] == 0xFF  # 45
        assert sig.mask[9] == 0xFF  # 08

    def test_complex_pat_line(self, parser):
        """Karisik wildcard'li uzun .pat satiri."""
        line = "4883EC28488D..........E8........4889C7 AB 0100 0200 :0000 _complex_func"
        sig = parser._parse_pat_line(line, "testlib")

        assert sig is not None
        assert sig.name == "_complex_func"
        assert sig.crc16 == 0xAB
        assert sig.size == 0x0100

    def test_comment_line(self, parser):
        """Yorum satiri None donmeli."""
        assert parser._parse_pat_line("# this is a comment", "lib") is None

    def test_separator_line(self, parser):
        """Separator satir None donmeli."""
        assert parser._parse_pat_line("---", "lib") is None

    def test_empty_line(self, parser):
        """Bos satir None donmeli."""
        assert parser._parse_pat_line("", "lib") is None

    def test_invalid_line(self, parser):
        """Gecersiz format None donmeli."""
        assert parser._parse_pat_line("this is not a valid pat line", "lib") is None

    def test_question_mark_name_skipped(self, parser):
        """? ile baslayan isimler (internal) atlanmali."""
        line = "558BEC83EC10 0C 0025 003A :0000 ?internal"
        sig = parser._parse_pat_line(line, "testlib")
        assert sig is None


# ---------------------------------------------------------------------------
# _hex_to_bytes_with_mask
# ---------------------------------------------------------------------------

class TestHexToBytesWithMask:
    """Hex to bytes+mask donusum testleri."""

    def test_all_fixed(self, parser):
        """Wildcard olmayan hex string."""
        pattern, mask = parser._hex_to_bytes_with_mask("558BEC")
        assert pattern == b"\x55\x8b\xec"
        assert mask == b"\xff\xff\xff"

    def test_all_wildcard(self, parser):
        """Tamami wildcard hex string."""
        pattern, mask = parser._hex_to_bytes_with_mask("......")
        assert pattern == b"\x00\x00\x00"
        assert mask == b"\x00\x00\x00"

    def test_mixed(self, parser):
        """Karisik fixed + wildcard."""
        pattern, mask = parser._hex_to_bytes_with_mask("55..EC")
        assert len(pattern) == 3
        assert len(mask) == 3
        assert pattern[0] == 0x55
        assert mask[0] == 0xFF
        assert pattern[1] == 0x00  # wildcard
        assert mask[1] == 0x00
        assert pattern[2] == 0xEC
        assert mask[2] == 0xFF

    def test_empty_string(self, parser):
        """Bos string bos sonuc donmeli."""
        pattern, mask = parser._hex_to_bytes_with_mask("")
        assert pattern == b""
        assert mask == b""

    def test_long_wildcard_run(self, parser):
        """Uzun wildcard serisi: ........"""
        pattern, mask = parser._hex_to_bytes_with_mask("........")
        assert len(pattern) == 4
        assert len(mask) == 4
        assert all(b == 0x00 for b in mask)

    def test_lowercase_hex(self, parser):
        """Kucuk harf hex."""
        pattern, mask = parser._hex_to_bytes_with_mask("ff00ab")
        assert pattern == b"\xff\x00\xab"
        assert mask == b"\xff\xff\xff"


# ---------------------------------------------------------------------------
# .pat dosya yukleme
# ---------------------------------------------------------------------------

class TestLoadPatFile:
    """PAT dosya yukleme testleri."""

    def test_load_valid_pat(self, parser, pat_file):
        """Gecerli .pat dosyasi yuklenebilir."""
        sigs = parser.load_pat_file(pat_file)
        assert len(sigs) == 3  # 3 fonksiyon satiri
        names = [s.name for s in sigs]
        assert "_my_function" in names
        assert "_another_func" in names
        assert "_complex_func" in names

    def test_load_nonexistent_pat(self, parser):
        """Var olmayan .pat dosyasi bos liste donmeli."""
        sigs = parser.load_pat_file("/nonexistent/path/foo.pat")
        assert sigs == []

    def test_pat_library_from_filename(self, parser, pat_file):
        """Library adi dosya adindan turetilmeli."""
        sigs = parser.load_pat_file(pat_file)
        assert all(s.library == "test_lib" for s in sigs)

    def test_empty_pat_file(self, parser, tmp_path):
        """Bos .pat dosyasi bos liste donmeli."""
        empty = tmp_path / "empty.pat"
        empty.write_text("")
        sigs = parser.load_pat_file(empty)
        assert sigs == []


# ---------------------------------------------------------------------------
# JSON signature yukleme
# ---------------------------------------------------------------------------

class TestLoadJsonSignatures:
    """JSON signature yukleme testleri."""

    def test_load_valid_json(self, parser, json_file):
        """Gecerli JSON dosyasi yuklenebilir."""
        sigs = parser.load_json_signatures(json_file)
        assert len(sigs) == 3
        names = [s.name for s in sigs]
        assert "_SSL_CTX_new" in names
        assert "_EVP_EncryptInit_ex" in names
        assert "_deflate" in names

    def test_json_fields(self, parser, json_file):
        """JSON'dan field'lar dogru okunuyor."""
        sigs = parser.load_json_signatures(json_file)
        ssl_sig = next(s for s in sigs if s.name == "_SSL_CTX_new")
        assert ssl_sig.library == "openssl"
        assert ssl_sig.category == "crypto"
        assert ssl_sig.purpose == "SSL context creation"
        assert ssl_sig.confidence == 0.85

    def test_json_byte_pattern(self, parser, json_file):
        """JSON'daki byte_pattern dogru okunuyor."""
        sigs = parser.load_json_signatures(json_file)
        deflate_sig = next(s for s in sigs if s.name == "_deflate")
        assert deflate_sig.byte_pattern == b"\x55\x8b\xec\x83\xec\x10"
        assert deflate_sig.mask == b"\xff" * 6

    def test_json_size_field(self, parser, json_file):
        """JSON'daki size fieldi dogru okunuyor."""
        sigs = parser.load_json_signatures(json_file)
        evp_sig = next(s for s in sigs if s.name == "_EVP_EncryptInit_ex")
        assert evp_sig.size == 256

    def test_nonexistent_json(self, parser):
        """Var olmayan JSON bos liste donmeli."""
        sigs = parser.load_json_signatures("/nonexistent/foo.json")
        assert sigs == []

    def test_invalid_json(self, parser, tmp_path):
        """Gecersiz JSON bos liste donmeli."""
        bad = tmp_path / "bad.json"
        bad.write_text("{invalid json")
        sigs = parser.load_json_signatures(bad)
        assert sigs == []

    def test_json_no_signatures_key(self, parser, tmp_path):
        """signatures anahtari olmayan JSON bos liste donmeli."""
        no_sigs = tmp_path / "no_sigs.json"
        no_sigs.write_text(json.dumps({"meta": {}, "total": 0}))
        sigs = parser.load_json_signatures(no_sigs)
        assert sigs == []

    def test_json_empty_name_skipped(self, parser, tmp_path):
        """Bos isimli entry atlanmali."""
        data = {
            "signatures": [
                {"name": "", "library": "test"},
                {"name": "_valid", "library": "test"},
            ],
        }
        jf = tmp_path / "skip.json"
        jf.write_text(json.dumps(data))
        sigs = parser.load_json_signatures(jf)
        assert len(sigs) == 1
        assert sigs[0].name == "_valid"


# ---------------------------------------------------------------------------
# Dizin tarama
# ---------------------------------------------------------------------------

class TestLoadDirectory:
    """Dizin tarama testleri."""

    def test_load_directory_mixed(self, parser, tmp_path, sample_pat_content, sample_json_content):
        """Dizindeki .pat ve .json dosyalari birlikte yuklenebilir."""
        (tmp_path / "lib.pat").write_text(sample_pat_content)
        (tmp_path / "sigs.json").write_text(json.dumps(sample_json_content))

        sigs = parser.load_directory(tmp_path)
        assert len(sigs) == 6  # 3 pat + 3 json

    def test_load_nonexistent_dir(self, parser):
        """Var olmayan dizin bos liste donmeli."""
        sigs = parser.load_directory("/nonexistent/dir")
        assert sigs == []

    def test_load_empty_dir(self, parser, tmp_path):
        """Bos dizin bos liste donmeli."""
        empty = tmp_path / "empty_dir"
        empty.mkdir()
        sigs = parser.load_directory(empty)
        assert sigs == []


# ---------------------------------------------------------------------------
# nm extraction (mock)
# ---------------------------------------------------------------------------

class TestExtractFromBinary:
    """Binary extraction testleri (subprocess mock ile)."""

    def test_extract_nonexistent_binary(self, parser):
        """Var olmayan binary bos liste donmeli."""
        sigs = parser.extract_from_binary("/nonexistent/lib.dylib")
        assert sigs == []

    def test_extract_no_nm(self, parser):
        """nm yoksa bos liste donmeli."""
        parser._nm_path = None
        with tempfile.NamedTemporaryFile(suffix=".dylib") as f:
            sigs = parser.extract_from_binary(f.name)
            assert sigs == []

    def test_extract_with_mock_nm(self, parser, tmp_path):
        """Mock nm ile symbol extraction."""
        # Gecici binary dosya olustur
        fake_bin = tmp_path / "libtest.dylib"
        fake_bin.write_bytes(b"\x00" * 100)

        nm_output = (
            "0000000100001000 T _test_function_one\n"
            "0000000100002000 T _test_function_two\n"
            "0000000100003000 D _test_data_var\n"
            "                 U _external_ref\n"
            "0000000100004000 T ___internal_func\n"
        )

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(
                stdout=nm_output,
                stderr="",
                returncode=0,
            )
            sigs = parser.extract_from_binary(fake_bin)

        # T tipi semboller: _test_function_one, _test_function_two
        # ___internal_func ___ prefix ile atlanmali
        # _test_data_var D tipi, dahil edilmemeli (sadece T)
        # _external_ref U tipi, dahil edilmemeli
        names = [s.name for s in sigs]
        assert "_test_function_one" in names
        assert "_test_function_two" in names
        assert "___internal_func" not in names
        assert "_test_data_var" not in names

    def test_extract_library_name_from_path(self, parser, tmp_path):
        """Library adi dosya adindan turetilir (lib prefix kaldirilir)."""
        fake_bin = tmp_path / "libcrypto.dylib"
        fake_bin.write_bytes(b"\x00" * 100)

        nm_output = "0000000100001000 T _EVP_Digest\n"
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(stdout=nm_output, stderr="", returncode=0)
            sigs = parser.extract_from_binary(fake_bin)

        assert len(sigs) == 1
        assert sigs[0].library == "crypto"  # "lib" prefix kaldirilmis

    def test_extract_custom_library_name(self, parser, tmp_path):
        """Kullanici tanimli library adi kullanilir."""
        fake_bin = tmp_path / "libfoo.dylib"
        fake_bin.write_bytes(b"\x00" * 100)

        nm_output = "0000000100001000 T _bar\n"
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(stdout=nm_output, stderr="", returncode=0)
            sigs = parser.extract_from_binary(fake_bin, library_name="custom_lib")

        assert sigs[0].library == "custom_lib"


# ---------------------------------------------------------------------------
# SignatureDB injection
# ---------------------------------------------------------------------------

class TestInjectIntoSignatureDB:
    """SignatureDB injection testleri."""

    def test_inject_basic(self, parser):
        """Temel injection calismali."""
        # Mock SignatureDB: sadece _symbol_db dict'i olan obje
        mock_db = mock.Mock()
        mock_db._symbol_db = {}
        # add_byte_signature mock
        mock_db.add_byte_signature = mock.Mock()

        sigs = [
            FLIRTSignature(name="_func1", library="lib1", category="cat1", purpose="test1"),
            FLIRTSignature(name="_func2", library="lib2", category="cat2", purpose="test2"),
        ]

        added_sym, added_bp = parser.inject_into_signature_db(mock_db, sigs)
        assert added_sym == 2
        assert "_func1" in mock_db._symbol_db
        assert "_func2" in mock_db._symbol_db
        assert mock_db._symbol_db["_func1"]["lib"] == "lib1"
        assert mock_db._symbol_db["_func1"]["purpose"] == "test1"

    def test_inject_duplicate_detection(self, parser):
        """Duplikasyon kontrolu calismali."""
        mock_db = mock.Mock()
        mock_db._symbol_db = {"_existing": {"lib": "old", "purpose": "", "category": "old"}}
        mock_db.add_byte_signature = mock.Mock()

        sigs = [
            FLIRTSignature(name="_existing", library="new_lib"),
            FLIRTSignature(name="_new_func", library="new_lib"),
        ]

        added_sym, _ = parser.inject_into_signature_db(mock_db, sigs)
        assert added_sym == 1
        # Mevcut entry degismemeli (builtin onceligi)
        assert mock_db._symbol_db["_existing"]["lib"] == "old"
        # Yeni entry eklenmeli
        assert "_new_func" in mock_db._symbol_db

    def test_inject_with_byte_pattern(self, parser):
        """Byte pattern'li signature'lar add_byte_signature ile eklenir."""
        mock_db = mock.Mock()
        mock_db._symbol_db = {}
        mock_db.add_byte_signature = mock.Mock()

        sigs = [
            FLIRTSignature(
                name="_func_with_bytes",
                library="lib",
                byte_pattern=b"\x55\x8b\xec",
                mask=b"\xff\xff\xff",
            ),
            FLIRTSignature(name="_func_no_bytes", library="lib"),
        ]

        added_sym, added_bp = parser.inject_into_signature_db(mock_db, sigs)
        assert added_sym == 2
        assert added_bp == 1  # Sadece byte_pattern olan icin
        mock_db.add_byte_signature.assert_called_once()

    def test_inject_no_symbol_db(self, parser):
        """_symbol_db attribute'u olmayan obje icin graceful fail."""
        bad_db = object()  # _symbol_db yok
        added_sym, added_bp = parser.inject_into_signature_db(bad_db, [])
        assert added_sym == 0
        assert added_bp == 0

    def test_inject_empty_name_skipped(self, parser):
        """Bos isimli signature atlanmali."""
        mock_db = mock.Mock()
        mock_db._symbol_db = {}
        mock_db.add_byte_signature = mock.Mock()

        sigs = [FLIRTSignature(name="", library="lib")]
        added_sym, _ = parser.inject_into_signature_db(mock_db, sigs)
        assert added_sym == 0


# ---------------------------------------------------------------------------
# match_function_bytes dogrulugu
# ---------------------------------------------------------------------------

class TestMatchFunctionBytes:
    """Byte pattern eslestirme testleri."""

    def test_exact_match(self, parser):
        """Tam eslestirme calismali."""
        sig = FLIRTSignature(
            name="_test_func",
            library="test",
            byte_pattern=b"\x55\x8b\xec",
            mask=b"\xff\xff\xff",
            confidence=0.95,
        )

        func_bytes = b"\x55\x8b\xec\x83\xec\x10"
        matches = parser.match_function_bytes(func_bytes, [sig])
        assert len(matches) == 1
        assert matches[0][0].name == "_test_func"
        assert matches[0][1] > 0.0

    def test_wildcard_match(self, parser):
        """Wildcard iceren pattern eslesmeli."""
        sig = FLIRTSignature(
            name="_wild_func",
            library="test",
            byte_pattern=b"\x55\x00\xec",
            mask=b"\xff\x00\xff",  # Ortadaki byte wildcard
            confidence=0.95,
        )

        # Ortadaki byte farkli ama wildcard oldugu icin eslesmeli
        func_bytes = b"\x55\xAA\xec\x00\x00"
        matches = parser.match_function_bytes(func_bytes, [sig])
        assert len(matches) == 1
        assert matches[0][0].name == "_wild_func"

    def test_no_match(self, parser):
        """Eslesmeme durumu."""
        sig = FLIRTSignature(
            name="_test",
            library="test",
            byte_pattern=b"\x55\x8b\xec",
            mask=b"\xff\xff\xff",
        )

        func_bytes = b"\x48\x89\xe5"  # Farkli byte'lar
        matches = parser.match_function_bytes(func_bytes, [sig])
        assert len(matches) == 0

    def test_too_short_bytes(self, parser):
        """Cok kisa func_bytes eslesmemeli."""
        sig = FLIRTSignature(
            name="_test",
            library="test",
            byte_pattern=b"\x55\x8b\xec\x83",
            mask=b"\xff\xff\xff\xff",
        )

        func_bytes = b"\x55\x8b"  # Pattern'den kisa
        matches = parser.match_function_bytes(func_bytes, [sig])
        assert len(matches) == 0

    def test_multiple_matches_sorted(self, parser):
        """Birden fazla eslestirme confidence'a gore siralanmali."""
        sig1 = FLIRTSignature(
            name="_func1",
            library="lib1",
            byte_pattern=b"\x55\x8b",
            mask=b"\xff\xff",
            confidence=0.80,
        )
        sig2 = FLIRTSignature(
            name="_func2",
            library="lib2",
            byte_pattern=b"\x55\x8b\xec\x83",
            mask=b"\xff\xff\xff\xff",  # Daha uzun pattern, daha yuksek confidence
            confidence=0.95,
        )

        func_bytes = b"\x55\x8b\xec\x83\xec\x10"
        matches = parser.match_function_bytes(func_bytes, [sig1, sig2])
        assert len(matches) == 2
        # sig2 daha yuksek confidence'la ilk olmali
        assert matches[0][0].name == "_func2"
        assert matches[0][1] > matches[1][1]

    def test_empty_signatures(self, parser):
        """Bos signature listesi bos sonuc donmeli."""
        matches = parser.match_function_bytes(b"\x55\x8b", [])
        assert matches == []

    def test_empty_func_bytes(self, parser):
        """Bos func_bytes bos sonuc donmeli."""
        sig = FLIRTSignature(
            name="_test",
            library="test",
            byte_pattern=b"\x55",
            mask=b"\xff",
        )
        matches = parser.match_function_bytes(b"", [sig])
        assert matches == []

    def test_no_byte_pattern_in_sig(self, parser):
        """Byte pattern'i olmayan signature atlanmali."""
        sig = FLIRTSignature(name="_no_bytes", library="lib")
        matches = parser.match_function_bytes(b"\x55\x8b", [sig])
        assert matches == []

    def test_mismatched_mask_length(self, parser):
        """Mask uzunlugu pattern'den farkli olan signature atlanmali."""
        sig = FLIRTSignature(
            name="_bad_mask",
            library="lib",
            byte_pattern=b"\x55\x8b\xec",
            mask=b"\xff\xff",  # 3 byte pattern, 2 byte mask -> atlanmali
        )
        matches = parser.match_function_bytes(b"\x55\x8b\xec", [sig])
        assert matches == []


# ---------------------------------------------------------------------------
# FLIRTSignature.to_dict
# ---------------------------------------------------------------------------

class TestFLIRTSignatureToDict:
    """FLIRTSignature serialization testi."""

    def test_to_dict(self):
        sig = FLIRTSignature(
            name="_test",
            library="testlib",
            category="crypto",
            purpose="test purpose",
            confidence=0.92,
            size=128,
        )
        d = sig.to_dict()
        assert d["name"] == "_test"
        assert d["library"] == "testlib"
        assert d["category"] == "crypto"
        assert d["purpose"] == "test purpose"
        assert d["confidence"] == 0.92
        assert d["size"] == 128

    def test_to_dict_default_category(self):
        """category bos ise library kullanilmali."""
        sig = FLIRTSignature(name="_f", library="mylib")
        d = sig.to_dict()
        assert d["category"] == "mylib"


# ---------------------------------------------------------------------------
# export_to_json
# ---------------------------------------------------------------------------

class TestExportToJson:
    """JSON export testleri."""

    def test_export_creates_file(self, parser, tmp_path):
        """Export dosya olusturur."""
        sigs = [
            FLIRTSignature(name="_func1", library="lib1"),
            FLIRTSignature(name="_func2", library="lib2", confidence=0.90),
        ]
        output = tmp_path / "output.json"
        parser.export_to_json(sigs, output)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 2
        assert len(data["signatures"]) == 2
        assert data["signatures"][0]["name"] == "_func1"

    def test_export_creates_parent_dirs(self, parser, tmp_path):
        """Olmayan ust dizinleri olusturur."""
        output = tmp_path / "deep" / "nested" / "dir" / "output.json"
        parser.export_to_json([], output)
        assert output.exists()

    def test_export_custom_meta(self, parser, tmp_path):
        """Ozel meta bilgisi eklenebilir."""
        output = tmp_path / "meta.json"
        meta = {"generator": "test", "version": "2.0", "custom": True}
        parser.export_to_json([], output, meta=meta)

        data = json.loads(output.read_text())
        assert data["meta"]["custom"] is True
        assert data["meta"]["version"] == "2.0"


# ---------------------------------------------------------------------------
# SignatureDB entegrasyonu (gercek SignatureDB ile)
# ---------------------------------------------------------------------------

class TestSignatureDBIntegration:
    """Gercek SignatureDB ile entegrasyon testleri."""

    def test_load_flirt_signatures_with_json(self, tmp_path):
        """SignatureDB.load_flirt_signatures JSON ile calismali."""
        from karadul.analyzers.signature_db import SignatureDB

        # Test JSON dosyasi olustur
        data = {
            "signatures": [
                {"name": "_flirt_test_func_1", "library": "test_flirt", "category": "test"},
                {"name": "_flirt_test_func_2", "library": "test_flirt", "category": "test"},
            ],
            "total": 2,
        }
        jf = tmp_path / "flirt_test.json"
        jf.write_text(json.dumps(data))

        # SignatureDB olustur ve yukle
        db = SignatureDB()
        initial_count = len(db._symbol_db)
        added = db.load_flirt_signatures([str(jf)])

        assert added == 2
        assert len(db._symbol_db) == initial_count + 2
        assert "_flirt_test_func_1" in db._symbol_db
        assert "_flirt_test_func_2" in db._symbol_db

    def test_load_flirt_signatures_with_pat(self, tmp_path):
        """SignatureDB.load_flirt_signatures PAT ile calismali."""
        from karadul.analyzers.signature_db import SignatureDB

        pat_content = "558BEC83EC10 0C 0025 003A :0000 _flirt_pat_func\n"
        pf = tmp_path / "test.pat"
        pf.write_text(pat_content)

        db = SignatureDB()
        initial_count = len(db._symbol_db)
        added = db.load_flirt_signatures([str(pf)])

        assert added == 1
        assert "_flirt_pat_func" in db._symbol_db

    def test_load_flirt_duplicate_protection(self, tmp_path):
        """Builtin DB'deki semboller uzerine yazilmamali."""
        from karadul.analyzers.signature_db import SignatureDB

        # _dispatch_async builtin DB'de var
        data = {
            "signatures": [
                {"name": "_dispatch_async", "library": "fake_lib", "category": "fake"},
                {"name": "_flirt_unique_func", "library": "test", "category": "test"},
            ],
            "total": 2,
        }
        jf = tmp_path / "dup_test.json"
        jf.write_text(json.dumps(data))

        db = SignatureDB()
        # _dispatch_async zaten builtin
        assert "_dispatch_async" in db._symbol_db
        original_lib = db._symbol_db["_dispatch_async"]["lib"]

        added = db.load_flirt_signatures([str(jf)])
        # Sadece unique func eklenmeli
        assert added == 1
        # Builtin degismemeli
        assert db._symbol_db["_dispatch_async"]["lib"] == original_lib

    def test_load_flirt_empty_paths(self):
        """Bos path listesi 0 donmeli."""
        from karadul.analyzers.signature_db import SignatureDB

        db = SignatureDB()
        added = db.load_flirt_signatures([])
        assert added == 0

    def test_load_flirt_nonexistent_paths(self):
        """Var olmayan path'ler graceful skip edilmeli."""
        from karadul.analyzers.signature_db import SignatureDB

        db = SignatureDB()
        added = db.load_flirt_signatures(["/nonexistent/foo.json", "/nope/bar.pat"])
        assert added == 0


# ---------------------------------------------------------------------------
# load_and_inject (convenience)
# ---------------------------------------------------------------------------

class TestLoadAndInject:
    """load_and_inject convenience metod testleri."""

    def test_load_and_inject_mixed(self, parser, tmp_path, sample_pat_content, sample_json_content):
        """Karisik dosya tipleri ile inject calismali."""
        (tmp_path / "lib.pat").write_text(sample_pat_content)
        (tmp_path / "sigs.json").write_text(json.dumps(sample_json_content))

        mock_db = mock.Mock()
        mock_db._symbol_db = {}
        mock_db.add_byte_signature = mock.Mock()

        total = parser.load_and_inject(
            mock_db,
            [str(tmp_path / "lib.pat"), str(tmp_path / "sigs.json")],
        )
        assert total > 0
        assert len(mock_db._symbol_db) > 0

    def test_load_and_inject_directory(self, parser, tmp_path, sample_pat_content):
        """Dizin path'i verilince dizini taramali."""
        sub = tmp_path / "sigdir"
        sub.mkdir()
        (sub / "a.pat").write_text(sample_pat_content)

        mock_db = mock.Mock()
        mock_db._symbol_db = {}
        mock_db.add_byte_signature = mock.Mock()

        total = parser.load_and_inject(mock_db, [str(sub)])
        assert total == 3  # 3 fonksiyon .pat'te

    def test_load_and_inject_unsupported_format(self, parser, tmp_path):
        """Desteklenmeyen dosya formati atlanmali."""
        weird = tmp_path / "weird.xml"
        weird.write_text("<xml/>")

        mock_db = mock.Mock()
        mock_db._symbol_db = {}

        total = parser.load_and_inject(mock_db, [str(weird)])
        assert total == 0


# ---------------------------------------------------------------------------
# _should_skip_symbol
# ---------------------------------------------------------------------------

class TestShouldSkipSymbol:
    """Sembol filtreleme testleri."""

    def test_skip_empty(self, parser):
        assert parser._should_skip_symbol("") is True

    def test_skip_triple_underscore(self, parser):
        assert parser._should_skip_symbol("___internal") is True

    def test_skip_objc_class(self, parser):
        assert parser._should_skip_symbol("_OBJC_CLASS_$_Foo") is True

    def test_skip_objc_metaclass(self, parser):
        assert parser._should_skip_symbol("_OBJC_METACLASS_$_Foo") is True

    def test_skip_objc_ivar(self, parser):
        assert parser._should_skip_symbol("_OBJC_IVAR_$_Foo._bar") is True

    def test_skip_short_name(self, parser):
        assert parser._should_skip_symbol("_x") is True  # clean = "x" (1 char)

    def test_allow_normal(self, parser):
        assert parser._should_skip_symbol("_SSL_CTX_new") is False

    def test_allow_underscore_prefix(self, parser):
        assert parser._should_skip_symbol("_my_func") is False

    def test_skip_ltmp(self, parser):
        assert parser._should_skip_symbol("ltmp0") is True

    def test_skip_global(self, parser):
        assert parser._should_skip_symbol("__GLOBAL__sub_I_main.cpp") is True
