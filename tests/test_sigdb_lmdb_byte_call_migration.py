"""B9 — JSON byte/call sig LMDB migration testleri.

build_sig_lmdb.py'in JSON kaynaklarindan byte ve call signature'lari LMDB'ye
yazmasini, ve sigdb_lmdb modulundeki yeni lookup/iter API'larini dogrular.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

lmdb = pytest.importorskip("lmdb")
msgpack = pytest.importorskip("msgpack")

from karadul.analyzers.sigdb_lmdb import (  # noqa: E402
    LMDBSignatureDB,
    byte_prefix_key,
)
from scripts.build_sig_lmdb import (  # noqa: E402
    iter_byte_sigs_from_json,
    iter_call_sigs_from_json,
    build,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def lmdb_path(tmp_path):
    return tmp_path / "test.lmdb"


@pytest.fixture
def fake_byte_sig_json(tmp_path):
    """Mini signatures_homebrew_bytes.json benzeri dosya."""
    path = tmp_path / "signatures_fake_bytes.json"
    data = {
        "meta": {"description": "fake byte sigs"},
        "signatures": [
            {
                "name": "_fake_func_a",
                "library": "fakelib",
                "category": "fake",
                "purpose": "test entry A",
                "confidence": 0.9,
                "size": 0,
                "byte_pattern": "deadbeef0102030405060708",
            },
            {
                "name": "_fake_func_b",
                "library": "fakelib",
                "category": "fake",
                "purpose": "test entry B",
                "confidence": 0.85,
                "size": 0,
                "byte_pattern": "cafebabe0a0b0c0d0e0f1011",
            },
            # Bozuk hex (skip edilmeli)
            {
                "name": "_bad_hex",
                "library": "fakelib",
                "byte_pattern": "XYZNOTHEX",
            },
            # Bos pattern (skip)
            {"name": "_no_pattern", "library": "fakelib"},
        ],
        "total": 4,
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def fake_call_sig_json(tmp_path):
    """call_signatures field'i iceren JSON."""
    path = tmp_path / "signatures_fake_calls.json"
    data = {
        "meta": {"description": "fake call sigs"},
        "call_signatures": [
            {
                "callees": ["malloc", "memset", "free"],
                "name": "alloc_zero_buf",
                "library": "libc",
                "purpose": "allocate + zero",
                "confidence": 0.8,
            },
            {
                "callees": ["AES_encrypt", "AES_decrypt"],
                "name": "aes_codec",
                "library": "openssl",
                "purpose": "aes wrapper",
                "confidence": 0.92,
            },
            # callees yok (skip)
            {"name": "no_callees", "library": "x"},
            # bos callees (skip)
            {"callees": [], "name": "empty", "library": "x"},
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Test 1: JSON parser yardimcilari
# ---------------------------------------------------------------------------


class TestIterByteSigsFromJson:
    def test_valid_entries_yielded(self, fake_byte_sig_json):
        entries = list(iter_byte_sigs_from_json(fake_byte_sig_json))
        assert len(entries) == 2
        names = {e["name"] for e in entries}
        assert names == {"_fake_func_a", "_fake_func_b"}

    def test_bad_hex_skipped(self, fake_byte_sig_json):
        entries = list(iter_byte_sigs_from_json(fake_byte_sig_json))
        names = {e["name"] for e in entries}
        assert "_bad_hex" not in names

    def test_no_pattern_skipped(self, fake_byte_sig_json):
        entries = list(iter_byte_sigs_from_json(fake_byte_sig_json))
        names = {e["name"] for e in entries}
        assert "_no_pattern" not in names

    def test_mask_default_all_ff(self, fake_byte_sig_json):
        entries = {e["name"]: e for e in iter_byte_sigs_from_json(fake_byte_sig_json)}
        a = entries["_fake_func_a"]
        # pattern 12 byte -> mask 24 hex char "ff"
        assert a["byte_mask_hex"] == "ff" * 12

    def test_nonexistent_file(self, tmp_path):
        entries = list(iter_byte_sigs_from_json(tmp_path / "yok.json"))
        assert entries == []

    def test_malformed_json(self, tmp_path):
        bad = tmp_path / "bozuk.json"
        bad.write_text("not json {{{", encoding="utf-8")
        entries = list(iter_byte_sigs_from_json(bad))
        assert entries == []


class TestIterCallSigsFromJson:
    def test_valid_entries_yielded(self, fake_call_sig_json):
        entries = list(iter_call_sigs_from_json(fake_call_sig_json))
        assert len(entries) == 2

    def test_empty_callees_skipped(self, fake_call_sig_json):
        entries = list(iter_call_sigs_from_json(fake_call_sig_json))
        names = {payload[0] for _, payload in entries}
        assert "empty" not in names
        assert "no_callees" not in names

    def test_callee_set_is_frozenset(self, fake_call_sig_json):
        entries = list(iter_call_sigs_from_json(fake_call_sig_json))
        for callees, _ in entries:
            assert isinstance(callees, frozenset)

    def test_confidence_is_float(self, fake_call_sig_json):
        entries = list(iter_call_sigs_from_json(fake_call_sig_json))
        for _, (_name, _lib, _purpose, conf) in entries:
            assert isinstance(conf, float)


# ---------------------------------------------------------------------------
# Test 2: Build pipeline - JSON sig'leri LMDB'ye yaziyor mu
# ---------------------------------------------------------------------------


class TestBuildJsonToLMDB:
    def test_build_writes_byte_sigs_from_json(
        self, tmp_path, fake_byte_sig_json
    ):
        # Mini proje root olarak tmp_path kullan; build sources'i tara
        output = tmp_path / "out.lmdb"
        summary = build(
            project_root=tmp_path,
            output=output,
            rebuild=True,
        )
        assert summary["status"] == "built"
        # LMDB'yi readonly ac, byte_sigs entry sayisi >= 2
        db = LMDBSignatureDB(output, readonly=True)
        try:
            stats = db.stats()
            assert stats.byte_sigs >= 2
        finally:
            db.close()

    def test_build_writes_call_sigs_from_json(
        self, tmp_path, fake_call_sig_json
    ):
        output = tmp_path / "out.lmdb"
        summary = build(project_root=tmp_path, output=output, rebuild=True)
        assert summary["status"] == "built"
        db = LMDBSignatureDB(output, readonly=True)
        try:
            stats = db.stats()
            assert stats.call_sigs >= 2
        finally:
            db.close()


# ---------------------------------------------------------------------------
# Test 3: Yeni lookup_byte_sig API
# ---------------------------------------------------------------------------


class TestLookupByteSig:
    def test_lookup_hit(self, lmdb_path):
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=32 * 1024 * 1024)
        db.bulk_write_byte_sigs([{
            "name": "test_sig_x",
            "library": "lib1",
            "byte_pattern_hex": "0102030405060708",
            "byte_mask_hex": "ff" * 8,
            "category": "test",
            "purpose": "lookup hit",
        }])
        db.sync()
        db.close()

        db = LMDBSignatureDB(lmdb_path, readonly=True)
        try:
            result = db.lookup_byte_sig("0102030405060708", "test_sig_x")
            assert result is not None
            assert result["name"] == "test_sig_x"
            assert result["library"] == "lib1"
        finally:
            db.close()

    def test_lookup_miss(self, lmdb_path):
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=32 * 1024 * 1024)
        db.bulk_write_byte_sigs([{
            "name": "a", "library": "l",
            "byte_pattern_hex": "aabbccdd11223344",
            "byte_mask_hex": "ff" * 8,
        }])
        db.sync()
        db.close()
        db = LMDBSignatureDB(lmdb_path, readonly=True)
        try:
            assert db.lookup_byte_sig("ffffffffffffffff", "b") is None
            # Yanlis name
            assert db.lookup_byte_sig("aabbccdd11223344", "yanlis") is None
        finally:
            db.close()

    def test_lookup_empty_args(self, lmdb_path):
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=32 * 1024 * 1024)
        db.sync()
        db.close()
        db = LMDBSignatureDB(lmdb_path, readonly=True)
        try:
            assert db.lookup_byte_sig("", "x") is None
            assert db.lookup_byte_sig("ff", "") is None
            assert db.lookup_byte_sig("XYZ", "x") is None  # bad hex
        finally:
            db.close()


# ---------------------------------------------------------------------------
# Test 4: iter_byte_sigs / iter_call_sigs / iter_string_sigs
# ---------------------------------------------------------------------------


class TestIteratorApi:
    def test_iter_byte_sigs_returns_all(self, lmdb_path):
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=32 * 1024 * 1024)
        entries = [
            {"name": f"sig_{i}", "library": "l",
             "byte_pattern_hex": f"{i:016x}",
             "byte_mask_hex": "ff" * 8}
            for i in range(10)
        ]
        db.bulk_write_byte_sigs(entries)
        db.sync()
        db.close()

        db = LMDBSignatureDB(lmdb_path, readonly=True)
        try:
            collected = list(db.iter_byte_sigs())
            assert len(collected) == 10
            assert {e["name"] for e in collected} == {f"sig_{i}" for i in range(10)}
        finally:
            db.close()

    def test_iter_call_sigs_returns_tuples(self, lmdb_path):
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=32 * 1024 * 1024)
        db.bulk_write_call_sigs([
            (frozenset(["a", "b"]), ("name1", "lib1", "purpose1", 0.7)),
            (frozenset(["x", "y", "z"]), ("name2", "lib2", "purpose2", 0.95)),
        ])
        db.sync()
        db.close()

        db = LMDBSignatureDB(lmdb_path, readonly=True)
        try:
            collected = list(db.iter_call_sigs())
            assert len(collected) == 2
            names = {t[0] for t in collected}
            assert names == {"name1", "name2"}
            # Format: 4-tuple
            for t in collected:
                assert len(t) == 4
        finally:
            db.close()

    def test_iter_string_sigs_returns_tuples(self, lmdb_path):
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=32 * 1024 * 1024)
        db.bulk_write_string_sigs([
            (frozenset(["hello", "world"]), ("greet", "tlib", "say hi")),
        ])
        db.sync()
        db.close()
        db = LMDBSignatureDB(lmdb_path, readonly=True)
        try:
            collected = list(db.iter_string_sigs())
            assert len(collected) == 1
            assert collected[0] == ("greet", "tlib", "say hi")
        finally:
            db.close()

    def test_iter_empty_db_returns_empty(self, lmdb_path):
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=32 * 1024 * 1024)
        db.sync()
        db.close()
        db = LMDBSignatureDB(lmdb_path, readonly=True)
        try:
            assert list(db.iter_byte_sigs()) == []
            assert list(db.iter_call_sigs()) == []
            assert list(db.iter_string_sigs()) == []
        finally:
            db.close()


# ---------------------------------------------------------------------------
# Test 5: End-to-end roundtrip: JSON -> build -> lookup
# ---------------------------------------------------------------------------


class TestEndToEndRoundtrip:
    def test_json_byte_sig_roundtrip(self, tmp_path, fake_byte_sig_json):
        output = tmp_path / "rt.lmdb"
        summary = build(project_root=tmp_path, output=output, rebuild=True)
        assert summary["status"] == "built"

        db = LMDBSignatureDB(output, readonly=True)
        try:
            result = db.lookup_byte_sig(
                "deadbeef0102030405060708", "_fake_func_a",
            )
            assert result is not None
            assert result["name"] == "_fake_func_a"
            assert result["library"] == "fakelib"
        finally:
            db.close()

    def test_json_call_sig_roundtrip(self, tmp_path, fake_call_sig_json):
        output = tmp_path / "rt.lmdb"
        summary = build(project_root=tmp_path, output=output, rebuild=True)
        assert summary["status"] == "built"

        db = LMDBSignatureDB(output, readonly=True)
        try:
            hit = db.lookup_call_sig(["AES_encrypt", "AES_decrypt"])
            assert hit is not None
            assert hit[0] == "aes_codec"
            assert hit[1] == "openssl"
        finally:
            db.close()
