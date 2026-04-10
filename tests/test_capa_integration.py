"""CAPA capability detection entegrasyonu testleri.

Mock CAPA output ile CAPAScanner ve stages entegrasyonunu test eder.
flare-capa kurulu olmasa da testler calismali (mock'lanmis).
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from karadul.analyzers.capa_scanner import (
    CAPACapability,
    CAPAScanResult,
    CAPAScanner,
    capability_to_function_name,
    rank_capabilities,
)


# -----------------------------------------------------------------------
# capability_to_function_name testleri
# -----------------------------------------------------------------------


class TestCapabilityToFunctionName:
    """capability_to_function_name utility fonksiyonu testleri."""

    def test_known_mapping_aes(self):
        assert capability_to_function_name("encrypt data using AES") == "aes_encrypt"

    def test_known_mapping_http(self):
        assert capability_to_function_name("send HTTP request") == "http_request_send"

    def test_known_mapping_mutex(self):
        assert capability_to_function_name("create mutex") == "mutex_create"

    def test_known_mapping_debugger(self):
        assert capability_to_function_name("check for debugger") == "debugger_check"

    def test_known_mapping_md5(self):
        assert capability_to_function_name("hash data using MD5") == "md5_hash"

    def test_known_mapping_base64_encode(self):
        assert capability_to_function_name("encode data using Base64") == "base64_encode"

    def test_generic_using_pattern(self):
        """'using X' pattern'i X'i prefix olarak alir."""
        name = capability_to_function_name("process data using XYZ")
        assert name.startswith("xyz_")

    def test_generic_via_pattern(self):
        """'via X' pattern'i X'i prefix olarak alir."""
        name = capability_to_function_name("persist via service")
        assert name.startswith("service_")

    def test_generic_simple(self):
        """Basit capability isimleri underscore-separated olur."""
        name = capability_to_function_name("enumerate network shares")
        assert "enumerate" in name
        assert "network" in name
        assert "_" in name
        # Ozel karakter yok
        assert name.isidentifier() or name.replace("_", "").isalnum()

    def test_max_length(self):
        """63 karakter limitini asmiyor."""
        long_name = "very long capability name that goes on and on and should be truncated to fit C identifier limit properly"
        result = capability_to_function_name(long_name)
        assert len(result) <= 63

    def test_numeric_start(self):
        """Rakamla baslayan isimler 'cap_' prefix alir."""
        # "3DES" gibi bir capability
        result = capability_to_function_name("3des encryption mode")
        assert not result[0].isdigit()
        assert result.startswith("cap_")

    def test_empty_string(self):
        result = capability_to_function_name("")
        assert result == ""


# -----------------------------------------------------------------------
# rank_capabilities testleri
# -----------------------------------------------------------------------


class TestRankCapabilities:
    """Capability siralama testleri."""

    def test_namespace_priority(self):
        """Daha uzun namespace = daha spesifik = daha yuksek sira."""
        caps = [
            CAPACapability(name="a", namespace="lib"),
            CAPACapability(name="b", namespace="lib/crypto/aes"),
            CAPACapability(name="c", namespace=""),
        ]
        ranked = rank_capabilities(caps)
        assert ranked[0].name == "b"  # en uzun namespace
        assert ranked[-1].name == "c"  # bos namespace

    def test_attack_bonus(self):
        """ATT&CK mapping'i olan capability daha bilgilendirici."""
        caps = [
            CAPACapability(name="short name", attack=[{"technique": "T1234"}]),
            CAPACapability(name="much longer name without attack"),
        ]
        ranked = rank_capabilities(caps)
        assert ranked[0].name == "short name"  # attack mapping var

    def test_name_length_tiebreaker(self):
        """Esit namespace ve attack'ta isim uzunlugu tiebreaker."""
        caps = [
            CAPACapability(name="ab"),
            CAPACapability(name="abcdef"),
        ]
        ranked = rank_capabilities(caps)
        assert ranked[0].name == "abcdef"

    def test_empty_list(self):
        assert rank_capabilities([]) == []


# -----------------------------------------------------------------------
# CAPAScanResult testleri
# -----------------------------------------------------------------------


class TestCAPAScanResult:
    """CAPAScanResult data class testleri."""

    def test_to_dict(self):
        result = CAPAScanResult(
            success=True,
            total_rules_matched=5,
            total_functions_matched=3,
            duration_seconds=1.234,
            format_="pe",
            arch="amd64",
            os_="windows",
            function_capabilities={
                "0x1000": [
                    CAPACapability(name="encrypt data using AES", namespace="crypto"),
                ],
            },
            file_capabilities=[
                CAPACapability(name="linked against OpenSSL"),
            ],
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["total_rules_matched"] == 5
        assert d["total_functions_matched"] == 3
        assert d["duration_seconds"] == 1.23
        assert d["format"] == "pe"
        assert "0x1000" in d["function_capabilities"]
        assert len(d["function_capabilities"]["0x1000"]) == 1
        assert d["function_capabilities"]["0x1000"][0]["name"] == "encrypt data using AES"
        assert len(d["file_capabilities"]) == 1

    def test_empty_result(self):
        result = CAPAScanResult()
        d = result.to_dict()
        assert d["success"] is False
        assert d["total_rules_matched"] == 0


# -----------------------------------------------------------------------
# CAPAScanner testleri
# -----------------------------------------------------------------------


class TestCAPAScanner:
    """CAPAScanner sinifi testleri."""

    def test_init_default_rules_path(self):
        scanner = CAPAScanner()
        assert scanner._rules_path == Path.home() / ".cache" / "karadul" / "capa-rules"

    def test_init_custom_rules_path(self):
        scanner = CAPAScanner(rules_path="/tmp/custom-rules")
        assert scanner._rules_path == Path("/tmp/custom-rules")

    def test_is_available_no_rules(self, tmp_path):
        """Kural dizini yoksa False."""
        scanner = CAPAScanner(rules_path=tmp_path / "nonexistent")
        assert scanner.is_available() is False

    def test_is_available_empty_rules(self, tmp_path):
        """Yeterli kural yoksa False."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Sadece 2 kural var (threshold 10)
        (rules_dir / "rule1.yml").write_text("test")
        (rules_dir / "rule2.yml").write_text("test")
        scanner = CAPAScanner(rules_path=rules_dir)
        assert scanner.is_available() is False

    def test_scan_unavailable(self, tmp_path):
        """CAPA mevcut degilse hata sonucu dondur."""
        scanner = CAPAScanner(rules_path=tmp_path / "nonexistent")
        result = scanner.scan(tmp_path / "binary")
        assert result.success is False
        assert len(result.errors) > 0

    def test_scan_nonexistent_binary(self, tmp_path):
        """Binary bulunamazsa hata sonucu dondur."""
        # CAPA available gibi gozuksun ama binary yok
        scanner = CAPAScanner()
        scanner._capa_available = True
        scanner._cli_path = "/usr/bin/false"
        result = scanner.scan(tmp_path / "nonexistent.exe")
        assert result.success is False

    def test_get_function_names(self):
        """CAPA sonuclarindan fonksiyon isim onerileri."""
        scanner = CAPAScanner()
        scan_result = CAPAScanResult(
            success=True,
            function_capabilities={
                "0x1000": [
                    CAPACapability(
                        name="encrypt data using AES",
                        namespace="data-manipulation/encryption/aes",
                    ),
                    CAPACapability(
                        name="create file",
                        namespace="host-interaction/file-system",
                    ),
                ],
                "0x2000": [
                    CAPACapability(name="send HTTP request"),
                ],
                "0x3000": [],  # Bos liste
            },
        )
        names = scanner.get_function_names(scan_result)
        assert "0x1000" in names
        # AES encrypt en spesifik (en uzun namespace)
        assert names["0x1000"] == "aes_encrypt"
        assert "0x2000" in names
        assert names["0x2000"] == "http_request_send"
        assert "0x3000" not in names  # Bos capability, isim yok

    def test_get_capability_comments(self):
        """CAPA sonuclarindan capability yorum satirlari."""
        scanner = CAPAScanner()
        scan_result = CAPAScanResult(
            success=True,
            function_capabilities={
                "0x1000": [
                    CAPACapability(
                        name="encrypt data using AES",
                        attack=[{"technique": "T1573.001", "tactic": "Command and Control"}],
                    ),
                    CAPACapability(name="create file"),
                ],
            },
        )
        comments = scanner.get_capability_comments(scan_result)
        assert "0x1000" in comments
        assert len(comments["0x1000"]) == 2
        assert "@capability encrypt data using AES" in comments["0x1000"][0]
        assert "ATT&CK" in comments["0x1000"][0]
        assert "@capability create file" in comments["0x1000"][1]


# -----------------------------------------------------------------------
# JSON parse testleri
# -----------------------------------------------------------------------


class TestParseJsonOutput:
    """CAPA JSON output parsing testleri."""

    @pytest.fixture()
    def sample_json(self):
        """Tipik bir CAPA JSON ciktisi."""
        return {
            "meta": {
                "analysis": {
                    "format": "pe",
                    "arch": "amd64",
                    "os": "windows",
                },
            },
            "rules": {
                "encrypt data using AES": {
                    "meta": {
                        "name": "encrypt data using AES",
                        "namespace": "data-manipulation/encryption/aes",
                        "description": "AES encryption detected",
                        "attack": [
                            {"technique": "T1573.001", "tactic": "Command and Control"},
                        ],
                        "mbc": [],
                        "lib": False,
                    },
                    "matches": [
                        [{"type": "absolute", "value": 4096}, {}],
                        [{"type": "absolute", "value": 8192}, {}],
                    ],
                },
                "send HTTP request": {
                    "meta": {
                        "name": "send HTTP request",
                        "namespace": "communication/http",
                        "description": "",
                        "attack": [],
                        "mbc": [],
                        "lib": False,
                    },
                    "matches": [
                        [{"type": "absolute", "value": 4096}, {}],
                    ],
                },
                "internal helper lib rule": {
                    "meta": {
                        "name": "internal helper",
                        "namespace": "lib",
                        "description": "",
                        "attack": [],
                        "mbc": [],
                        "lib": True,  # lib rule, atlanmali
                    },
                    "matches": [
                        [{"type": "absolute", "value": 12288}, {}],
                    ],
                },
                "file level cap": {
                    "meta": {
                        "name": "file level cap",
                        "namespace": "",
                        "description": "",
                        "attack": [],
                        "mbc": [],
                        "lib": False,
                    },
                    "matches": [
                        [{"type": "no address", "value": 0}, {}],
                    ],
                },
            },
        }

    def test_parse_basic(self, sample_json):
        scanner = CAPAScanner()
        result = scanner._parse_json_output(sample_json)

        assert result.success is True
        assert result.format_ == "pe"
        assert result.arch == "amd64"
        assert result.os_ == "windows"
        # 4 kural ama 1 lib rule atlanir -> 3 non-lib match
        assert result.total_rules_matched == 4

    def test_parse_function_capabilities(self, sample_json):
        scanner = CAPAScanner()
        result = scanner._parse_json_output(sample_json)

        # 0x1000 (4096) iki capability'ye sahip: AES + HTTP
        assert "0x1000" in result.function_capabilities
        cap_names = [c.name for c in result.function_capabilities["0x1000"]]
        assert "encrypt data using AES" in cap_names
        assert "send HTTP request" in cap_names

        # 0x2000 (8192) bir capability'ye sahip: AES
        assert "0x2000" in result.function_capabilities
        assert len(result.function_capabilities["0x2000"]) == 1

    def test_parse_lib_rules_skipped(self, sample_json):
        """Lib kurallar atlanmali."""
        scanner = CAPAScanner()
        result = scanner._parse_json_output(sample_json)

        # 0x3000 (12288) sadece lib rule'dan geliyor, atlanmali
        assert "0x3000" not in result.function_capabilities

    def test_parse_file_capabilities(self, sample_json):
        scanner = CAPAScanner()
        result = scanner._parse_json_output(sample_json)

        assert len(result.file_capabilities) >= 1
        file_cap_names = [c.name for c in result.file_capabilities]
        assert "file level cap" in file_cap_names

    def test_parse_attack_mapping(self, sample_json):
        scanner = CAPAScanner()
        result = scanner._parse_json_output(sample_json)

        aes_caps = [
            c for c in result.function_capabilities.get("0x1000", [])
            if c.name == "encrypt data using AES"
        ]
        assert len(aes_caps) == 1
        assert len(aes_caps[0].attack) == 1
        assert aes_caps[0].attack[0]["technique"] == "T1573.001"

    def test_parse_empty_rules(self):
        scanner = CAPAScanner()
        result = scanner._parse_json_output({"meta": {}, "rules": {}})
        assert result.success is True
        assert result.total_rules_matched == 0
        assert len(result.function_capabilities) == 0


# -----------------------------------------------------------------------
# _inject_capa_comments testleri
# -----------------------------------------------------------------------


class TestInjectCapaComments:
    """stages.py'deki _inject_capa_comments helper testleri."""

    def test_inject_comments_basic(self, tmp_path):
        """Basit bir C dosyasina CAPA capability yorumlari ekleme."""
        from karadul.stages import _inject_capa_comments

        # C dosyasi olustur
        c_file = tmp_path / "test.c"
        c_file.write_text(textwrap.dedent("""\
            void FUN_00001000(int param1)
            {
                return;
            }

            int FUN_00002000(void)
            {
                return 0;
            }
        """))

        # CAPA capability'leri (addr -> [cap_dict, ...])
        capa_caps = {
            "0x1000": [
                {"name": "encrypt data using AES", "namespace": "crypto/aes"},
                {"name": "create file", "namespace": "host-interaction"},
            ],
        }

        # func_data: addr -> name mapping
        func_data = {
            "functions": [
                {"address": "0x1000", "name": "FUN_00001000"},
                {"address": "0x2000", "name": "FUN_00002000"},
            ],
        }

        count = _inject_capa_comments(tmp_path, capa_caps, func_data)

        assert count == 1  # Sadece FUN_00001000'a yorum eklendi

        result = c_file.read_text()
        assert "@capability encrypt data using AES" in result
        assert "@capability create file" in result
        # FUN_00002000'a yorum eklenmemeli (capa'da yok)
        # Ama fonksiyon tanimi hala durmali
        assert "FUN_00002000" in result

    def test_inject_comments_no_match(self, tmp_path):
        """Eslesen fonksiyon yoksa hicbir sey eklenmez."""
        from karadul.stages import _inject_capa_comments

        c_file = tmp_path / "test.c"
        c_file.write_text("void other_func(void) { return; }\n")

        capa_caps = {
            "0x9999": [{"name": "some capability"}],
        }
        func_data = {
            "functions": [
                {"address": "0x9999", "name": "missing_func"},
            ],
        }

        count = _inject_capa_comments(tmp_path, capa_caps, func_data)
        assert count == 0

    def test_inject_comments_empty(self, tmp_path):
        """Bos capa sonucu."""
        from karadul.stages import _inject_capa_comments

        count = _inject_capa_comments(tmp_path, {}, None)
        assert count == 0

    def test_inject_comments_no_func_data(self, tmp_path):
        """func_data olmadan calisir (fonksiyon eslestirme yapilamaz)."""
        from karadul.stages import _inject_capa_comments

        c_file = tmp_path / "test.c"
        c_file.write_text("void FUN_00001000(void) { return; }\n")

        capa_caps = {
            "0x1000": [{"name": "encrypt data"}],
        }

        count = _inject_capa_comments(tmp_path, capa_caps, None)
        assert count == 0  # func_data olmadan addr->name eslestirme yapilamaz


# -----------------------------------------------------------------------
# Config testleri
# -----------------------------------------------------------------------


class TestCAPAConfig:
    """CAPA config ayarlari testleri."""

    def test_default_config(self):
        from karadul.config import BinaryReconstructionConfig

        cfg = BinaryReconstructionConfig()
        assert cfg.enable_capa is True
        assert cfg.capa_rules_path == ""
        assert cfg.capa_timeout == 600

    def test_name_merger_has_capa_weight(self):
        from karadul.config import NameMergerConfig

        cfg = NameMergerConfig()
        assert "capa_capability" in cfg.source_weights
        assert cfg.source_weights["capa_capability"] == 0.85
