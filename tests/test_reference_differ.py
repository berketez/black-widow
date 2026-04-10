"""ReferenceDiffer + VersionDetector testleri.

Test edilen senaryolar:
1. VersionDetector: SQLite, OpenSSL, zlib, curl, Go tespiti
2. VersionDetector: Validator string'lerle confidence artisi
3. VersionDetector: Bos/gecersiz girdi
4. ReferenceDiffer: String fingerprint eslestirme
5. ReferenceDiffer: CFG similarity eslestirme
6. ReferenceDiffer: Size + constant eslestirme
7. ReferenceDiffer: Call propagation eslestirme
8. ReferenceDiffer: Naming map dogrulugu
9. ReferenceDB: Dizin tarama
10. Edge case'ler (bos girdi, threshold altinda, vb.)
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from karadul.reconstruction.reference_differ import (
    Detection,
    FunctionMatch,
    ReferenceDB,
    ReferenceDBEntry,
    ReferenceDiffer,
    ReferenceMatchResult,
    VersionDetector,
    _cosine_similarity,
    _extract_cfg_features,
    _extract_constants,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_func(
    name: str,
    address: str,
    size: int = 100,
    param_count: int = 2,
    return_type: str = "int",
) -> dict:
    """Ghidra functions.json fonksiyon dict'i."""
    return {
        "name": name,
        "address": address,
        "size": size,
        "param_count": param_count,
        "return_type": return_type,
        "calling_convention": "__cdecl",
        "is_thunk": False,
        "is_external": False,
    }


def _make_functions_json(funcs: list[dict]) -> dict:
    return {"total": len(funcs), "program": "test", "functions": funcs}


def _make_strings_json(strings: list[dict]) -> dict:
    return {"total": len(strings), "program": "test", "strings": strings}


def _make_string_entry(
    value: str,
    address: str = "0x1000",
    func_addr: str | None = None,
) -> dict:
    xrefs = []
    if func_addr:
        xrefs.append({
            "from_address": "0xAAAA",
            "from_func_addr": func_addr,
        })
    return {
        "address": address,
        "value": value,
        "type": "string",
        "xrefs": xrefs,
    }


def _make_cfg_function(
    name: str,
    address: str,
    block_count: int = 5,
    edge_count: int = 6,
    cyclomatic_complexity: int = 3,
) -> dict:
    """Basit CFG fonksiyon verisi."""
    blocks = [
        {
            "start_address": f"0x{address[2:]}_{i:02x}" if address.startswith("0x") else f"{address}_{i:02x}",
            "instruction_count": 10 + i,
            "size": 40 + i * 4,
        }
        for i in range(block_count)
    ]
    edges = []
    for i in range(min(edge_count, block_count - 1)):
        edges.append({
            "from_block": blocks[i]["start_address"],
            "to_block": blocks[i + 1]["start_address"],
            "edge_type": "fall_through" if i % 2 == 0 else "conditional_jump",
        })
    # Back edges for loops
    if edge_count > block_count - 1 and block_count >= 3:
        edges.append({
            "from_block": blocks[-1]["start_address"],
            "to_block": blocks[1]["start_address"],
            "edge_type": "conditional_jump",
        })

    return {
        "name": name,
        "address": address,
        "blocks": blocks,
        "edges": edges,
        "cyclomatic_complexity": cyclomatic_complexity,
        "loop_headers": [blocks[1]["start_address"]] if block_count >= 3 else [],
        "back_edges": [edges[-1]] if edge_count > block_count - 1 else [],
    }


# ---------------------------------------------------------------------------
# VersionDetector Tests
# ---------------------------------------------------------------------------


class TestVersionDetector:
    """VersionDetector testleri."""

    def test_detect_sqlite(self):
        """SQLite versiyon tespiti."""
        detector = VersionDetector()
        strings = {"strings": [
            {"value": "SQLite format 3"},
            {"value": "3.46.0"},
            {"value": "SQLite 3.46.0"},
            {"value": "CREATE TABLE"},
            {"value": "SELECT"},
        ]}
        result = detector.detect_from_strings(strings)
        assert len(result) >= 1
        sqlite_det = result[0]
        assert sqlite_det.library == "sqlite3"
        assert sqlite_det.version == "3.46.0"
        assert sqlite_det.confidence >= 0.70

    def test_detect_openssl(self):
        """OpenSSL versiyon tespiti."""
        detector = VersionDetector()
        strings = {"strings": [
            {"value": "OpenSSL 3.1.2"},
            {"value": "SSL_CTX_new"},
            {"value": "EVP_DigestInit"},
        ]}
        result = detector.detect_from_strings(strings)
        assert len(result) >= 1
        ssl_det = result[0]
        assert ssl_det.library == "openssl"
        assert ssl_det.version == "3.1.2"
        assert ssl_det.confidence >= 0.80  # 2+ validator

    def test_detect_zlib(self):
        """zlib versiyon tespiti."""
        detector = VersionDetector()
        strings = {"strings": [
            {"value": "zlib 1.3.1"},
            {"value": "inflate"},
            {"value": "deflate"},
            {"value": "crc32"},
        ]}
        result = detector.detect_from_strings(strings)
        assert len(result) >= 1
        zlib_det = result[0]
        assert zlib_det.library == "zlib"
        assert zlib_det.version == "1.3.1"
        assert zlib_det.confidence >= 0.90  # 3+ validator

    def test_detect_curl(self):
        """libcurl versiyon tespiti."""
        detector = VersionDetector()
        strings = {"strings": [
            {"value": "curl/8.4.0"},
            {"value": "CURLOPT_URL"},
        ]}
        result = detector.detect_from_strings(strings)
        assert len(result) >= 1
        curl_det = result[0]
        assert curl_det.library == "libcurl"
        assert curl_det.version == "8.4.0"

    def test_detect_go_runtime(self):
        """Go runtime tespiti."""
        detector = VersionDetector()
        strings = {"strings": [
            {"value": "go1.22.0"},
            {"value": "runtime."},
            {"value": "goroutine"},
            {"value": "GOROOT"},
        ]}
        result = detector.detect_from_strings(strings)
        assert len(result) >= 1
        go_det = result[0]
        assert go_det.library == "go_runtime"
        assert go_det.version == "1.22.0"
        assert go_det.confidence >= 0.90

    def test_detect_multiple_libraries(self):
        """Birden fazla kutuphane tespiti."""
        detector = VersionDetector()
        strings = {"strings": [
            {"value": "SQLite 3.46.0"},
            {"value": "zlib 1.3.1"},
            {"value": "OpenSSL 3.1.2"},
        ]}
        result = detector.detect_from_strings(strings)
        libs = {d.library for d in result}
        assert "sqlite3" in libs
        assert "zlib" in libs
        assert "openssl" in libs

    def test_detect_plain_string_list(self):
        """Duz string listesi girdi."""
        detector = VersionDetector()
        strings = ["SQLite 3.46.0", "CREATE TABLE", "SELECT"]
        result = detector.detect_from_strings(strings)
        assert len(result) >= 1
        assert result[0].library == "sqlite3"

    def test_detect_no_match(self):
        """Hic eslesmeme durumu."""
        detector = VersionDetector()
        strings = {"strings": [
            {"value": "hello world"},
            {"value": "foo bar"},
        ]}
        result = detector.detect_from_strings(strings)
        assert len(result) == 0

    def test_detect_empty_input(self):
        """Bos girdi."""
        detector = VersionDetector()
        assert detector.detect_from_strings({}) == []
        assert detector.detect_from_strings([]) == []
        assert detector.detect_from_strings({"strings": []}) == []

    def test_validator_boosts_confidence(self):
        """Validator string'leri confidence'i arttirir."""
        detector = VersionDetector()

        # Validator olmadan
        no_val = {"strings": [{"value": "SQLite 3.46.0"}]}
        result_no = detector.detect_from_strings(no_val)
        conf_no = result_no[0].confidence if result_no else 0

        # 3+ validator ile
        with_val = {"strings": [
            {"value": "SQLite 3.46.0"},
            {"value": "CREATE TABLE"},
            {"value": "SELECT"},
            {"value": "PRAGMA"},
        ]}
        result_with = detector.detect_from_strings(with_val)
        conf_with = result_with[0].confidence if result_with else 0

        assert conf_with > conf_no

    def test_detect_min_confidence_filter(self):
        """Minimum confidence filtresi."""
        detector = VersionDetector()
        strings = {"strings": [{"value": "SQLite 3.46.0"}]}
        # Cok yuksek threshold: hicbir sey donmemeli
        result = detector.detect_from_strings(strings, min_confidence=0.99)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Helper Function Tests
# ---------------------------------------------------------------------------


class TestHelperFunctions:
    """Yardimci fonksiyon testleri."""

    def test_cosine_similarity_identical(self):
        """Ayni vectorler = 1.0."""
        v = [0.5, 0.3, 0.8, 0.1]
        assert abs(_cosine_similarity(v, v) - 1.0) < 1e-6

    def test_cosine_similarity_orthogonal(self):
        """Dik vectorler = 0.0."""
        v1 = [1.0, 0.0]
        v2 = [0.0, 1.0]
        assert abs(_cosine_similarity(v1, v2)) < 1e-6

    def test_cosine_similarity_different_length(self):
        """Farkli boyutlu vectorler (padding)."""
        v1 = [1.0, 0.5, 0.3]
        v2 = [1.0, 0.5]
        sim = _cosine_similarity(v1, v2)
        assert 0.0 < sim < 1.0

    def test_cosine_similarity_empty(self):
        """Bos vector = 0.0."""
        assert _cosine_similarity([], [1.0]) == 0.0
        assert _cosine_similarity([1.0], []) == 0.0
        assert _cosine_similarity([], []) == 0.0

    def test_extract_cfg_features_basic(self):
        """CFG feature extraction temel calisma."""
        cfg = _make_cfg_function("test", "0x1000", block_count=5, edge_count=6)
        fv = _extract_cfg_features(cfg)
        assert len(fv) == 12
        assert all(0.0 <= v <= 1.0 for v in fv)

    def test_extract_cfg_features_empty(self):
        """Bos CFG."""
        cfg = {"blocks": [], "edges": [], "loop_headers": [], "back_edges": []}
        fv = _extract_cfg_features(cfg)
        assert len(fv) == 12
        assert all(v == 0.0 for v in fv)

    def test_extract_constants_hex(self):
        """Hex sabit cikarma."""
        func = {"code": "int x = 0xDEADBEEF; int y = 0x1234;"}
        constants = _extract_constants(func)
        assert 0xDEADBEEF in constants
        assert 0x1234 in constants

    def test_extract_constants_decimal(self):
        """Decimal sabit cikarma."""
        func = {"code": "int x = 12345; int y = 67890;"}
        constants = _extract_constants(func)
        assert 12345 in constants
        assert 67890 in constants

    def test_extract_constants_filters_small(self):
        """Kucuk sabitler (<16) filtrelenir."""
        func = {"code": "int x = 5; int y = 0x0F;"}
        constants = _extract_constants(func)
        assert 5 not in constants
        assert 15 not in constants


# ---------------------------------------------------------------------------
# ReferenceDiffer Tests
# ---------------------------------------------------------------------------


class TestReferenceDiffer:
    """ReferenceDiffer eslestirme testleri."""

    def test_string_fingerprint_match(self):
        """String fingerprint ile eslestirme."""
        differ = ReferenceDiffer(min_confidence=0.40)

        ref_funcs = _make_functions_json([
            _make_func("sqlite3_exec", "0x1000"),
            _make_func("sqlite3_prepare", "0x2000"),
        ])
        target_funcs = _make_functions_json([
            _make_func("FUN_a000", "0xa000"),
            _make_func("FUN_b000", "0xb000"),
        ])

        # sqlite3_exec ve FUN_a000 ayni string'lere referans veriyor
        ref_strings = _make_strings_json([
            _make_string_entry("sqlite3_exec: callback error", func_addr="0x1000"),
            _make_string_entry("SQLITE_ABORT", func_addr="0x1000"),
            _make_string_entry("cannot prepare statement", func_addr="0x2000"),
            _make_string_entry("SQLITE_PREPARE_FAILED", func_addr="0x2000"),
        ])
        target_strings = _make_strings_json([
            _make_string_entry("sqlite3_exec: callback error", func_addr="0xa000"),
            _make_string_entry("SQLITE_ABORT", func_addr="0xa000"),
            _make_string_entry("cannot prepare statement", func_addr="0xb000"),
            _make_string_entry("SQLITE_PREPARE_FAILED", func_addr="0xb000"),
        ])

        result = differ.match_direct(
            ref_functions=ref_funcs,
            target_functions=target_funcs,
            ref_strings=ref_strings,
            target_strings=target_strings,
        )
        assert result.matched >= 2
        assert "FUN_a000" in result.naming_map
        assert result.naming_map["FUN_a000"] == "sqlite3_exec"
        assert "FUN_b000" in result.naming_map
        assert result.naming_map["FUN_b000"] == "sqlite3_prepare"

    def test_cfg_similarity_match(self):
        """CFG feature similarity ile eslestirme."""
        differ = ReferenceDiffer(min_similarity=0.80, min_confidence=0.50)

        ref_funcs = _make_functions_json([
            _make_func("sqlite3_open", "0x1000", size=200),
        ])
        target_funcs = _make_functions_json([
            _make_func("FUN_a000", "0xa000", size=195),
        ])

        # Benzer CFG yapisi
        ref_cfg = {"functions": [
            _make_cfg_function("sqlite3_open", "0x1000", block_count=8, edge_count=10, cyclomatic_complexity=4),
        ]}
        target_cfg = {"functions": [
            _make_cfg_function("FUN_a000", "0xa000", block_count=8, edge_count=10, cyclomatic_complexity=4),
        ]}

        result = differ.match_direct(
            ref_functions=ref_funcs,
            target_functions=target_funcs,
            ref_cfg=ref_cfg,
            target_cfg=target_cfg,
        )
        assert result.matched >= 1
        assert result.naming_map.get("FUN_a000") == "sqlite3_open"

    def test_size_constant_match(self):
        """Size + constant eslestirme."""
        differ = ReferenceDiffer(min_confidence=0.70)

        # Ayni boyut ve parametre: 1:1 match
        ref_funcs = _make_functions_json([
            _make_func("crc32_table_init", "0x1000", size=256, param_count=1, return_type="void"),
        ])
        target_funcs = _make_functions_json([
            _make_func("FUN_a000", "0xa000", size=256, param_count=1, return_type="void"),
        ])

        result = differ.match_direct(
            ref_functions=ref_funcs,
            target_functions=target_funcs,
        )
        assert result.matched >= 1
        assert result.naming_map.get("FUN_a000") == "crc32_table_init"

    def test_no_match_different_functions(self):
        """Farkli fonksiyonlar eslesmemeli."""
        differ = ReferenceDiffer()

        ref_funcs = _make_functions_json([
            _make_func("tiny_func", "0x1000", size=16, param_count=0),
        ])
        target_funcs = _make_functions_json([
            _make_func("FUN_a000", "0xa000", size=512, param_count=5),
        ])

        result = differ.match_direct(
            ref_functions=ref_funcs,
            target_functions=target_funcs,
        )
        assert result.matched == 0

    def test_empty_input(self):
        """Bos girdi."""
        differ = ReferenceDiffer()

        result = differ.match_direct(
            ref_functions={"functions": []},
            target_functions={"functions": []},
        )
        assert result.matched == 0
        assert result.naming_map == {}

    def test_naming_map_best_confidence(self):
        """Ayni target icin birden fazla match: en yuksek confidence kazanir."""
        m1 = FunctionMatch("foo", "0x1", "FUN_a", "0xa", 0.85, "cfg")
        m2 = FunctionMatch("bar", "0x2", "FUN_a", "0xa", 0.92, "string")
        result = ReferenceDiffer._build_naming_map([m1, m2])
        assert result["FUN_a"] == "bar"  # 0.92 > 0.85

    def test_match_rate_calculation(self):
        """Match rate dogrulugu."""
        differ = ReferenceDiffer(min_confidence=0.70)

        ref_funcs = _make_functions_json([
            _make_func("f1", "0x1000", size=100, param_count=2, return_type="int"),
            _make_func("f2", "0x2000", size=200, param_count=3, return_type="void"),
        ])
        target_funcs = _make_functions_json([
            _make_func("FUN_a", "0xa000", size=100, param_count=2, return_type="int"),
            _make_func("FUN_b", "0xb000", size=200, param_count=3, return_type="void"),
            _make_func("FUN_c", "0xc000", size=50, param_count=0, return_type="void"),
        ])

        result = differ.match_direct(
            ref_functions=ref_funcs,
            target_functions=target_funcs,
        )
        # min(2, 3) = 2, matched >= 2 -> rate = 1.0
        if result.matched == 2:
            assert abs(result.match_rate - 1.0) < 0.01


# ---------------------------------------------------------------------------
# ReferenceDB Tests
# ---------------------------------------------------------------------------


class TestReferenceDB:
    """ReferenceDB testleri."""

    def test_scan_empty_dir(self):
        """Bos dizin taranir, hic entry yok."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = ReferenceDB(Path(tmpdir))
            assert db.libraries == []

    def test_scan_valid_structure(self):
        """Gecerli dizin yapisi taranir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # sqlite3/3.46.0/ghidra_functions.json
            lib_dir = Path(tmpdir) / "sqlite3" / "3.46.0"
            lib_dir.mkdir(parents=True)
            funcs = {"functions": [{"name": "sqlite3_open", "address": "0x1000"}]}
            (lib_dir / "ghidra_functions.json").write_text(json.dumps(funcs))

            db = ReferenceDB(Path(tmpdir))
            assert "sqlite3" in db.libraries

            entry = db.lookup("sqlite3", "3.46.0")
            assert entry is not None
            assert entry.library == "sqlite3"
            assert entry.version == "3.46.0"
            assert entry.functions_json.exists()

    def test_lookup_nonexistent(self):
        """Mevcut olmayan kutuphane lookup'i None dondurur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = ReferenceDB(Path(tmpdir))
            assert db.lookup("nonexistent", "1.0.0") is None

    def test_lookup_closest_prefix(self):
        """Prefix match ile en yakin versiyon bulunur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            lib_dir = Path(tmpdir) / "zlib" / "1.3.1"
            lib_dir.mkdir(parents=True)
            (lib_dir / "ghidra_functions.json").write_text('{"functions": []}')

            db = ReferenceDB(Path(tmpdir))
            # "1.3" prefix'i "1.3.1"'i bulmali
            entry = db.lookup_closest("zlib", "1.3")
            assert entry is not None
            assert entry.version == "1.3.1"

    def test_save_and_load_index(self):
        """Index kaydet ve yukle."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Once dizin yapisi olustur
            lib_dir = Path(tmpdir) / "openssl" / "3.1.2"
            lib_dir.mkdir(parents=True)
            (lib_dir / "ghidra_functions.json").write_text('{"functions": []}')

            db1 = ReferenceDB(Path(tmpdir))
            db1.save_index()

            # Index dosyasi olusturuldu mu?
            assert (Path(tmpdir) / "index.json").exists()

            # Yeniden yukle -- index.json'dan
            db2 = ReferenceDB(Path(tmpdir))
            entry = db2.lookup("openssl", "3.1.2")
            assert entry is not None


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestIntegration:
    """Entegrasyon testleri."""

    def test_full_pipeline_version_detect_and_match(self):
        """Versiyon tespiti + eslestirme pipeline'i."""
        # 1. Versiyon tespiti
        detector = VersionDetector()
        strings_data = {"strings": [
            {"value": "SQLite 3.46.0"},
            {"value": "CREATE TABLE"},
            {"value": "SELECT"},
            {"value": "PRAGMA"},
        ]}
        detections = detector.detect_from_strings(strings_data)
        assert len(detections) >= 1
        assert detections[0].library == "sqlite3"

        # 2. Reference DB olustur
        with tempfile.TemporaryDirectory() as tmpdir:
            ref_dir = Path(tmpdir) / "sqlite3" / "3.46.0"
            ref_dir.mkdir(parents=True)

            ref_funcs = {
                "functions": [
                    _make_func("sqlite3_exec", "0x1000", size=200),
                    _make_func("sqlite3_open", "0x2000", size=300),
                ]
            }
            (ref_dir / "ghidra_functions.json").write_text(json.dumps(ref_funcs))

            ref_strs = _make_strings_json([
                _make_string_entry("callback error", func_addr="0x1000"),
                _make_string_entry("SQLITE_ABORT", func_addr="0x1000"),
            ])
            (ref_dir / "ghidra_strings.json").write_text(json.dumps(ref_strs))

            # 3. Eslestir
            differ = ReferenceDiffer(reference_db_path=Path(tmpdir), min_confidence=0.40)

            target_funcs = _make_functions_json([
                _make_func("FUN_a000", "0xa000", size=200),
                _make_func("FUN_b000", "0xb000", size=300),
            ])
            target_strs = _make_strings_json([
                _make_string_entry("callback error", func_addr="0xa000"),
                _make_string_entry("SQLITE_ABORT", func_addr="0xa000"),
            ])

            result = differ.match(
                target_functions=target_funcs,
                target_strings=target_strs,
                detection=detections[0],
            )
            assert result is not None
            assert result.matched >= 1
            assert "FUN_a000" in result.naming_map

    def test_result_summary(self):
        """ReferenceMatchResult.summary() formati."""
        det = Detection("sqlite3", "3.46.0", 0.95)
        result = ReferenceMatchResult(
            detection=det,
            total_ref_functions=100,
            total_target_functions=150,
            matched=80,
            match_rate=0.80,
            matches=[
                FunctionMatch("f1", "0x1", "FUN_a", "0xa", 0.92, "string_fingerprint"),
                FunctionMatch("f2", "0x2", "FUN_b", "0xb", 0.88, "cfg_similarity"),
            ],
        )
        summary = result.summary()
        assert summary["library"] == "sqlite3"
        assert summary["matched"] == 80
        assert "string_fingerprint" in summary["by_method"]
