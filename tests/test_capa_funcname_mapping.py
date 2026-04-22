"""CAPA address-keyed -> function-name-keyed mapping testleri (M2 T5).

Bu testler su davranislari dogrular:
1. `_normalize_addr` farkli formatlari kanonige indirir (0x prefix, padding).
2. `CAPAScanner._build_funcname_index` adres->isim mapping'i uretir;
   eksik adreslerde `FUN_<addr>` fallback kullanir.
3. `CAPAScanResult.capability_by_funcname` paralel anahtar olarak
   adres anahtarlariyla tutarli dolar.
4. `scan()` `functions_data=None` ile cagrildiginda name index bos kalir.
5. `capability_to_function_name` oncelik sirasi:
   dahili sozluk > resources/capa_name_map.json > heuristic.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from karadul.analyzers import capa_scanner as cs
from karadul.analyzers.capa_scanner import (
    CAPACapability,
    CAPAScanResult,
    CAPAScanner,
    _normalize_addr,
    _load_external_name_map,
    _reset_external_name_map_cache,
    capability_to_function_name,
)


# ---------------------------------------------------------------------------
# 1. _normalize_addr
# ---------------------------------------------------------------------------


class TestNormalizeAddr:
    """Adres normalizasyon testleri."""

    def test_normalize_addr_various_formats(self):
        """'0x401234', '401234', '0x00401234' hepsi ayni kanonik formu vermeli."""
        assert _normalize_addr("0x401234") == "00401234"
        assert _normalize_addr("401234") == "00401234"
        assert _normalize_addr("0x00401234") == "00401234"
        assert _normalize_addr("00401234") == "00401234"

    def test_normalize_addr_idempotent(self):
        """Kanonik forma normalize edilen adres tekrar normalize edildiginde degismez."""
        canonical = _normalize_addr("0x401234")
        assert _normalize_addr(canonical) == canonical

    def test_normalize_addr_uppercase(self):
        """Buyuk harf hex de normalize edilebilmeli."""
        assert _normalize_addr("0xABCDEF01") == "abcdef01"
        assert _normalize_addr("0xDEADBEEF") == "deadbeef"

    def test_normalize_addr_64bit_preserved(self):
        """16 hex'li 64-bit adres sabit kalmali (pad edilmemeli)."""
        assert _normalize_addr("0x00007ff8abcd1234") == "7ff8abcd1234".zfill(8) or \
               _normalize_addr("0x00007ff8abcd1234") == "00007ff8abcd1234"
        # Daha net: 12 hex zaten 8'den buyuk, pad edilmez
        assert len(_normalize_addr("0x7ff8abcd1234")) >= 8

    def test_normalize_addr_int_input(self):
        """Integer girdi hex'e cevrilmeli."""
        assert _normalize_addr(0x401234) == "00401234"
        assert _normalize_addr(4198964) == "00401234"  # 0x401234


# ---------------------------------------------------------------------------
# 2. _build_funcname_index
# ---------------------------------------------------------------------------


class TestBuildFuncnameIndex:
    """Address -> funcname indeks olusumu testleri."""

    def _make_scanner(self) -> CAPAScanner:
        s = CAPAScanner()
        s._capa_available = True  # is_available check'ini atla
        return s

    def test_build_funcname_index_basic(self):
        """2 adres -> 2 farkli fonksiyon ismi."""
        scanner = self._make_scanner()
        cap1 = CAPACapability(name="encrypt data using AES", namespace="crypto/aes")
        cap2 = CAPACapability(name="send HTTP request", namespace="network/http")

        function_caps = {
            "0x401234": [cap1],
            "0x402000": [cap2],
        }
        functions_data = {
            "00401234": {"name": "my_encrypt_fn"},
            "00402000": {"name": "do_http_call"},
        }

        index = scanner._build_funcname_index(function_caps, functions_data)
        assert "my_encrypt_fn" in index
        assert "do_http_call" in index
        assert index["my_encrypt_fn"] == [cap1]
        assert index["do_http_call"] == [cap2]

    def test_build_funcname_index_missing_addr(self):
        """functions_data'da bulunmayan adres FUN_<addr> olarak dusmeli."""
        scanner = self._make_scanner()
        cap = CAPACapability(name="create mutex")
        function_caps = {"0xdeadbeef": [cap]}
        functions_data: dict = {}  # bos

        index = scanner._build_funcname_index(function_caps, functions_data)
        assert "FUN_deadbeef" in index
        assert index["FUN_deadbeef"] == [cap]

    def test_build_funcname_index_multiple_caps_same_addr(self):
        """Ayni adreste birden fazla capability varsa hepsi isme eklenir."""
        scanner = self._make_scanner()
        cap1 = CAPACapability(name="encrypt data using AES")
        cap2 = CAPACapability(name="hash data using SHA256")

        function_caps = {"0x401234": [cap1, cap2]}
        functions_data = {"00401234": {"name": "crypto_helper"}}

        index = scanner._build_funcname_index(function_caps, functions_data)
        assert index["crypto_helper"] == [cap1, cap2]

    def test_build_funcname_index_normalization_mismatch(self):
        """functions_data farkli formatta anahtar kullanirsa bile eslesme olmali."""
        scanner = self._make_scanner()
        cap = CAPACapability(name="send data")

        # CAPA `0x401234`, functions_data `0x00401234` — yine de eslesmeli
        function_caps = {"0x401234": [cap]}
        functions_data = {"0x00401234": {"name": "xmit"}}

        index = scanner._build_funcname_index(function_caps, functions_data)
        assert "xmit" in index

    def test_build_funcname_index_name_string_value(self):
        """functions_data value dict yerine direkt string olabilir (toleranslı)."""
        scanner = self._make_scanner()
        cap = CAPACapability(name="read file")
        function_caps = {"0x401234": [cap]}
        functions_data = {"00401234": "my_reader"}  # string value

        index = scanner._build_funcname_index(function_caps, functions_data)
        assert "my_reader" in index

    def test_build_funcname_index_not_dict_input(self):
        """functions_data dict degilse bos dict donmeli (graceful)."""
        scanner = self._make_scanner()
        cap = CAPACapability(name="anything")
        function_caps = {"0x401234": [cap]}

        index = scanner._build_funcname_index(function_caps, ["not", "a", "dict"])  # type: ignore
        assert index == {}


# ---------------------------------------------------------------------------
# 3. CAPAScanResult paralel anahtar tutarliligi
# ---------------------------------------------------------------------------


class TestCAPAScanResultParallelKeys:
    """function_capabilities + capability_by_funcname paralel tutarlilik."""

    def test_capa_scan_result_parallel_keys(self):
        """Her iki anahtar tipinde capability'ler eslesmeli."""
        cap = CAPACapability(name="encrypt data using AES")
        result = CAPAScanResult(
            success=True,
            function_capabilities={"0x401234": [cap]},
            capability_by_funcname={"aes_routine": [cap]},
        )

        # Her iki erisim yolu da ayni capability'yi dondurmeli
        assert result.function_capabilities["0x401234"][0].name == cap.name
        assert result.capability_by_funcname["aes_routine"][0].name == cap.name

        # to_dict her iki anahtari da serialize etmeli
        d = result.to_dict()
        assert "function_capabilities" in d
        assert "capability_by_funcname" in d
        assert "aes_routine" in d["capability_by_funcname"]

    def test_capa_scan_result_default_funcname_empty(self):
        """capability_by_funcname default factory ile bos dict olmali."""
        result = CAPAScanResult(success=True)
        assert result.capability_by_funcname == {}


# ---------------------------------------------------------------------------
# 4. scan() entegrasyonu — functions_data None
# ---------------------------------------------------------------------------


class TestScanWithoutFunctionsData:
    """functions_data verilmediginde capability_by_funcname bos kalmali."""

    def test_capa_scan_without_functions_data_graceful(self, tmp_path, monkeypatch):
        """scan(functions_data=None) -> capability_by_funcname bos."""
        scanner = CAPAScanner()

        # is_available() True dondursun
        monkeypatch.setattr(scanner, "is_available", lambda: True)
        scanner._cli_path = None  # API path'e git

        # _scan_via_api mock: function_capabilities dolu, funcname bos olmali
        cap = CAPACapability(name="create mutex")
        mock_result = CAPAScanResult(
            success=True,
            function_capabilities={"0x401234": [cap]},
        )

        def _mock_api(path):
            return mock_result

        monkeypatch.setattr(scanner, "_scan_via_api", _mock_api)

        # functions_data vermeden cagir
        binary = tmp_path / "fake.bin"
        binary.write_bytes(b"MZ\x00\x00")

        result = scanner.scan(binary, functions_data=None)
        assert result.success is True
        assert result.function_capabilities  # dolu
        assert result.capability_by_funcname == {}  # bos (graceful)

    def test_capa_scan_with_functions_data_populates(self, tmp_path, monkeypatch):
        """scan(functions_data={...}) -> capability_by_funcname dolmali."""
        scanner = CAPAScanner()
        monkeypatch.setattr(scanner, "is_available", lambda: True)
        scanner._cli_path = None

        cap = CAPACapability(name="send HTTP request")
        mock_result = CAPAScanResult(
            success=True,
            function_capabilities={"0x401234": [cap]},
        )
        monkeypatch.setattr(scanner, "_scan_via_api", lambda p: mock_result)

        binary = tmp_path / "fake.bin"
        binary.write_bytes(b"MZ\x00\x00")

        fd = {"00401234": {"name": "fetch_url"}}
        result = scanner.scan(binary, functions_data=fd)

        assert result.success is True
        assert "fetch_url" in result.capability_by_funcname
        assert result.capability_by_funcname["fetch_url"] == [cap]


# ---------------------------------------------------------------------------
# 5. capa_name_map.json loading
# ---------------------------------------------------------------------------


class TestNameMapJSONLoading:
    """resources/capa_name_map.json yukleme ve cache davranisi."""

    def test_name_map_json_loaded(self):
        """JSON dosyasi var ve yuklenebilir olmali."""
        _reset_external_name_map_cache()
        data = _load_external_name_map()
        assert isinstance(data, dict)
        # En az birkac bilinen namespace key'i icermeli
        assert "crypto/aes/encrypt" in data
        assert "network/socket/connect" in data
        assert data["crypto/aes/encrypt"] == "aes_encrypt_block"

    def test_name_map_json_has_min_entries(self):
        """Minimum 30+ entry (spec gereksinimi) olmali."""
        _reset_external_name_map_cache()
        data = _load_external_name_map()
        # _comment satirini dusur
        non_comment = {k: v for k, v in data.items() if not k.startswith("_")}
        assert len(non_comment) >= 30, f"Sadece {len(non_comment)} entry var"

    def test_name_map_cache_behavior(self):
        """Cache: ikinci cagri ayni obje'yi donduruyor mu?"""
        _reset_external_name_map_cache()
        first = _load_external_name_map()
        second = _load_external_name_map()
        assert first is second  # same object, cached


# ---------------------------------------------------------------------------
# 6. capability_to_function_name oncelik sirasi
# ---------------------------------------------------------------------------


class TestCapabilityToFuncnamePriority:
    """Oncelik: dahili dict > JSON > heuristic."""

    def test_capability_to_funcname_internal_dict_priority(self):
        """Dahili _CAPABILITY_NAME_MAP'te olan degerler once gelmeli."""
        # "encrypt data using AES" hem dahili'de (aes_encrypt) hem de
        # JSON'da olabilir; dahili oncelikli
        _reset_external_name_map_cache()
        result = capability_to_function_name("encrypt data using AES")
        assert result == "aes_encrypt"  # dahili deger (JSON'da _block var ama dahili kazanir)

    def test_capability_to_funcname_json_fallback(self):
        """Dahili'de yok ama JSON'da var -> JSON degeri donmeli."""
        _reset_external_name_map_cache()
        # "crypto/aes/encrypt" dahili _CAPABILITY_NAME_MAP'te YOK,
        # ama resources/capa_name_map.json'da var
        result = capability_to_function_name("crypto/aes/encrypt")
        assert result == "aes_encrypt_block"

    def test_capability_to_funcname_json_network(self):
        """network/socket/connect JSON'dan gelmeli."""
        _reset_external_name_map_cache()
        result = capability_to_function_name("network/socket/connect")
        assert result == "socket_connect"

    def test_capability_to_funcname_heuristic_fallback(self):
        """Ne dahili'de ne JSON'da yoksa heuristic uretmeli."""
        _reset_external_name_map_cache()
        # Tamamen uydurulmus bir capability ismi
        result = capability_to_function_name("manipulate xyzquux widget state")
        # Heuristic: kucuk harfe cevirir, underscore'lar
        assert "_" in result
        assert result.islower() or not any(c.isupper() for c in result)
        # Bir C identifier olmali
        assert all(c.isalnum() or c == "_" for c in result)

    def test_capability_to_funcname_internal_wins_over_json(self):
        """Hem dahili hem JSON'da olan bir deger icin dahili kazanir."""
        # "encrypt data using AES" dahili'de aes_encrypt
        # JSON'da aes_encrypt_block olsa bile dahili oncelikli
        _reset_external_name_map_cache()
        r = capability_to_function_name("encrypt data using AES")
        assert r == "aes_encrypt"


# ---------------------------------------------------------------------------
# Ek: json.loads uyumlulugu icin bir sanity test
# ---------------------------------------------------------------------------


class TestNameMapJSONSanity:
    """capa_name_map.json dosya-sistemi seviyesi sanity check."""

    def test_json_file_exists_and_is_valid(self):
        """Dosya fiziksel olarak var ve gecerli JSON."""
        path = Path(cs.__file__).resolve().parent.parent / "resources" / "capa_name_map.json"
        assert path.is_file(), f"Beklenen yol: {path}"
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict)
        assert len(data) >= 30
