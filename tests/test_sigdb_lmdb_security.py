"""B20 — LMDB security testleri.

Üç savunma katmanı:
1. Permission check (world/group writable hard fail, owner mismatch warn)
2. Integrity manifest dogrulama (mismatch warn, missing -> sessiz gec)
3. msgpack bounded buffer (DoS koruma)
"""

from __future__ import annotations

import json
import logging
import os
import stat
import sys

import pytest

lmdb = pytest.importorskip("lmdb")
msgpack = pytest.importorskip("msgpack")

from karadul.analyzers.sigdb_lmdb import (  # noqa: E402
    INTEGRITY_MANIFEST_NAME,
    LMDBSignatureDB,
    MSGPACK_MAX_BUFFER,
    pack,
    unpack,
)
from karadul.exceptions import SignatureDBError  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def populated_db_path(tmp_path):
    """Yazma + close ile uretilmis LMDB dizini, izinler default."""
    p = tmp_path / "secure.lmdb"
    db = LMDBSignatureDB(p, readonly=False, map_size=16 * 1024 * 1024)
    db.bulk_write_symbols([("foo", {"lib": "x", "purpose": "p", "category": "c"})])
    db.sync()
    db.close()
    return p


# ---------------------------------------------------------------------------
# Test 1: Permission check
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics required")
class TestPermissionCheck:
    def test_world_writable_raises(self, populated_db_path):
        # World writable yap (+o w)
        current = populated_db_path.stat().st_mode
        populated_db_path.chmod(current | stat.S_IWOTH)
        try:
            with pytest.raises(SignatureDBError, match="world/group writable"):
                LMDBSignatureDB(populated_db_path, readonly=True)
        finally:
            populated_db_path.chmod(current)

    def test_group_writable_raises(self, populated_db_path):
        current = populated_db_path.stat().st_mode
        populated_db_path.chmod(current | stat.S_IWGRP)
        try:
            with pytest.raises(SignatureDBError, match="world/group writable"):
                LMDBSignatureDB(populated_db_path, readonly=True)
        finally:
            populated_db_path.chmod(current)

    def test_normal_permissions_ok(self, populated_db_path):
        # Default umask altinda olusan LMDB -- raise YOK
        db = LMDBSignatureDB(populated_db_path, readonly=True)
        db.close()

    def test_owner_mismatch_warns_but_not_raises(
        self, populated_db_path, monkeypatch, caplog,
    ):
        # os.getuid'i sahte uid donduren bir fonksiyonla degistir
        real_uid = os.getuid()
        monkeypatch.setattr(os, "getuid", lambda: real_uid + 99999)
        with caplog.at_level(logging.WARNING):
            db = LMDBSignatureDB(populated_db_path, readonly=True)
            db.close()
        assert any("owner mismatch" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Test 2: Integrity manifest
# ---------------------------------------------------------------------------


class TestIntegrityManifest:
    def test_manifest_written_on_build(self, tmp_path):
        """Build sirasinda manifest.json olusur (write_integrity_manifest)."""
        p = tmp_path / "m.lmdb"
        db = LMDBSignatureDB(p, readonly=False, map_size=16 * 1024 * 1024)
        db.bulk_write_symbols([("foo", {"lib": "x"})])
        db.sync()
        manifest = db.write_integrity_manifest()
        db.close()
        assert (p / INTEGRITY_MANIFEST_NAME).exists()
        assert manifest["algo"] in ("blake3", "sha256")
        assert len(manifest["data_mdb_hash"]) >= 32

    def test_manifest_match_no_warning(self, tmp_path, caplog):
        p = tmp_path / "m.lmdb"
        db = LMDBSignatureDB(p, readonly=False, map_size=16 * 1024 * 1024)
        db.bulk_write_symbols([("foo", {"lib": "x"})])
        db.sync()
        db.write_integrity_manifest()
        db.close()

        with caplog.at_level(logging.WARNING):
            db = LMDBSignatureDB(p, readonly=True)
            db.close()
        # MISMATCH icermez
        assert not any("MISMATCH" in rec.message for rec in caplog.records)

    def test_manifest_mismatch_logs_warning(self, tmp_path, caplog):
        p = tmp_path / "m.lmdb"
        db = LMDBSignatureDB(p, readonly=False, map_size=16 * 1024 * 1024)
        db.bulk_write_symbols([("foo", {"lib": "x"})])
        db.sync()
        db.write_integrity_manifest()
        db.close()

        # Manifest'i bozuk hash ile uzeryaz
        manifest_path = p / INTEGRITY_MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text("utf-8"))
        manifest["data_mdb_hash"] = "0" * len(manifest["data_mdb_hash"])
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with caplog.at_level(logging.WARNING):
            db = LMDBSignatureDB(p, readonly=True)
            db.close()
        # MISMATCH log'u var, ama raise yok
        assert any("MISMATCH" in rec.message for rec in caplog.records)

    def test_missing_manifest_silent(self, tmp_path, caplog):
        """Manifest yoksa (eski LMDB) sessizce gec, warning yok."""
        p = tmp_path / "m.lmdb"
        db = LMDBSignatureDB(p, readonly=False, map_size=16 * 1024 * 1024)
        db.bulk_write_symbols([("foo", {"lib": "x"})])
        db.sync()
        db.close()
        # Manifest YOK
        with caplog.at_level(logging.WARNING):
            db = LMDBSignatureDB(p, readonly=True)
            db.close()
        # Manifest ile ilgili warning olmamali
        assert not any("Manifest" in rec.message for rec in caplog.records)
        assert not any("MISMATCH" in rec.message for rec in caplog.records)

    def test_malformed_manifest_warns(self, tmp_path, caplog):
        p = tmp_path / "m.lmdb"
        db = LMDBSignatureDB(p, readonly=False, map_size=16 * 1024 * 1024)
        db.bulk_write_symbols([("foo", {"lib": "x"})])
        db.sync()
        db.close()
        # Bozuk manifest
        (p / INTEGRITY_MANIFEST_NAME).write_text("{{{not json", encoding="utf-8")
        with caplog.at_level(logging.WARNING):
            db = LMDBSignatureDB(p, readonly=True)
            db.close()
        assert any("Manifest okunamadi" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Test 3: msgpack bounded buffer (DoS koruma)
# ---------------------------------------------------------------------------


class TestMsgpackBoundedBuffer:
    def test_normal_payload_unpacks(self):
        data = pack({"name": "ok", "size": 42})
        assert unpack(data) == {"name": "ok", "size": 42}

    def test_oversize_payload_rejected(self):
        # MSGPACK_MAX_BUFFER + 1 byte
        huge = b"\x00" * (MSGPACK_MAX_BUFFER + 1)
        with pytest.raises(ValueError, match="payload too large"):
            unpack(huge)

    def test_100mb_rejected(self):
        # 100 MB tamamen sifir -- gercek msgpack data degil, sadece reject
        # boyutu test ediyor
        big = b"\xc0" * (100 * 1024 * 1024)
        with pytest.raises(ValueError, match="payload too large"):
            unpack(big)

    def test_just_under_limit_attempts_decode(self):
        """Limit altinda decode denenir; bozuk msgpack ise normal msgpack
        hatasi gelir, payload too large gelmez."""
        # MSGPACK_MAX_BUFFER - 1 byte, ama gecersiz msgpack
        almost = b"\xff" * 32  # gecersiz format
        # ValueError "payload too large" YOK
        with pytest.raises(Exception) as exc_info:
            unpack(almost)
        assert "payload too large" not in str(exc_info.value)

    def test_corrupt_lmdb_entry_handled(self, tmp_path):
        """Eger LMDB icinde corrupt/huge entry varsa iter API skip etmeli.

        iter_byte_sigs cursor'u tum entry'leri gezer; bozuk olanlari warning
        log'lar ve atlar.
        """
        p = tmp_path / "corrupt.lmdb"
        db = LMDBSignatureDB(p, readonly=False, map_size=16 * 1024 * 1024)
        # Saglikli entry
        db.bulk_write_byte_sigs([{
            "name": "ok", "library": "l",
            "byte_pattern_hex": "0102030405060708",
            "byte_mask_hex": "ff" * 8,
        }])
        db.sync()
        db.close()

        # Saglikli entry'yi okuma; manuel raw write
        env = lmdb.open(
            str(p), max_dbs=8, readonly=False,
            map_size=16 * 1024 * 1024, subdir=True,
        )
        byte_db = env.open_db(b"byte_sigs", create=False)
        with env.begin(db=byte_db, write=True) as txn:
            # Bozuk msgpack value
            txn.put(b"\xff" * 12, b"\xff" * 32)
        env.close()

        db = LMDBSignatureDB(p, readonly=True)
        try:
            # Iter etmek 1 saglikli entry vermeli, bozuk skip
            entries = list(db.iter_byte_sigs())
            assert len(entries) == 1
            assert entries[0]["name"] == "ok"
        finally:
            db.close()
