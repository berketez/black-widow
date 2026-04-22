"""v1.10.0 C4: LMDB metadata ayrimi (symbols DB kirliligi onleme) testleri.

Onceki implementasyonda ``put_metadata("k", v)`` ``__meta__:k`` key'ini
symbols DB'sine yaziyordu. Sonuc:
  * ``stats().symbols`` meta entry'leri de sayiyordu.
  * Cursor iterasyonu ``__meta__:`` prefix'li entry'leri goruyordu.

Fix (C4): Ayri ``_DB_META`` named DB + ``max_dbs=5``. ``stats()`` symbols
DB'sindeki legacy ``__meta__:`` prefix'li entry'leri hesaptan dusurur
(backward compat).
"""

from __future__ import annotations

import pytest

lmdb = pytest.importorskip("lmdb")
msgpack = pytest.importorskip("msgpack")

from karadul.analyzers.sigdb_lmdb import (  # noqa: E402
    _DB_META,
    _DB_SYMBOLS,
    LMDBSignatureDB,
    pack,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def writable_db(tmp_path):
    db = LMDBSignatureDB(tmp_path / "test.lmdb", readonly=False,
                         map_size=32 * 1024 * 1024)
    yield db
    if not db._closed:
        db.close()


# ---------------------------------------------------------------------------
# Test: Metadata symbols DB'sine yazilmiyor (ayri DB)
# ---------------------------------------------------------------------------


class TestMetadataIsolation:
    """Meta DB ile symbols DB birbirine karismamali."""

    def test_stats_does_not_count_metadata(self, writable_db):
        """put_metadata cagrisi stats().symbols'i artirmamali."""
        # Once 3 gercek sembol yaz
        writable_db.bulk_write_symbols([
            ("_malloc", {"lib": "libc", "purpose": "alloc", "category": "mem"}),
            ("_free", {"lib": "libc", "purpose": "dealloc", "category": "mem"}),
            ("_realloc", {"lib": "libc", "purpose": "realloc", "category": "mem"}),
        ])
        # 5 tane metadata ekle
        writable_db.put_metadata("source_hash", b"abc123")
        writable_db.put_metadata("build_time", b"1700000000")
        writable_db.put_metadata("source_count", b"42")
        writable_db.put_metadata("string_sig_count", b"100")
        writable_db.put_metadata("byte_sig_count", b"50")

        s = writable_db.stats()
        assert s.symbols == 3, (
            f"Metadata symbols'i kirletti. Beklenen 3, gelen {s.symbols}. "
            "C4 fix: _DB_META ayri named DB."
        )

    def test_metadata_roundtrip(self, writable_db):
        """put_metadata + get_metadata dogru deger dondurur."""
        writable_db.put_metadata("source_hash", b"deadbeefcafe")
        retrieved = writable_db.get_metadata("source_hash")
        assert retrieved == b"deadbeefcafe"

    def test_metadata_missing_returns_none(self, writable_db):
        """Var olmayan meta key None dondurmeli."""
        assert writable_db.get_metadata("nonexistent_key") is None

    def test_metadata_not_present_in_symbols_db_directly(self, writable_db):
        """``source_hash`` key'i symbols DB'sinde direkt aramada olmamali."""
        writable_db.put_metadata("source_hash", b"v1")

        # Symbols DB'sinde direkt key araya bak -- meta'ya ait olmamali
        with writable_db._env.begin(db=writable_db._db_symbols) as txn:
            raw = txn.get(b"source_hash")
            assert raw is None, (
                "Metadata symbols DB'sine yazildi -- ayri DB kullanilmiyor."
            )

    def test_metadata_present_in_meta_db(self, writable_db):
        """Yazilan meta gercekten _DB_META named DB'ye gitmis mi?"""
        writable_db.put_metadata("foo_key", b"bar_val")

        with writable_db._env.begin(db=writable_db._db_meta) as txn:
            raw = txn.get(b"foo_key")
            assert raw == b"bar_val"


class TestMetadataBackwardCompat:
    """Legacy __meta__: prefix'li LMDB'ler hala okunabilmeli."""

    def test_legacy_meta_prefix_still_readable(self, writable_db):
        """Eski LMDB'de symbols DB'sine __meta__: prefix ile yazilmis
        metadata -> get_metadata() fallback yapabilmeli."""
        # Eski davranisi simule et: __meta__:legacy_key symbols DB'ye
        with writable_db._env.begin(db=writable_db._db_symbols, write=True) as txn:
            txn.put(b"__meta__:legacy_key", b"legacy_value")

        # Yeni get_metadata onlari da donmeli (yeni DB'de yok)
        result = writable_db.get_metadata("legacy_key")
        assert result == b"legacy_value", (
            "Legacy __meta__: fallback okumadi."
        )

    def test_stats_excludes_legacy_meta_pollution(self, writable_db):
        """Legacy __meta__: entry'leri symbols DB'sinde olsa bile
        stats().symbols onlari saymamali."""
        # 2 gercek sembol
        writable_db.bulk_write_symbols([
            ("_alpha", {"lib": "x", "purpose": "", "category": ""}),
            ("_beta", {"lib": "x", "purpose": "", "category": ""}),
        ])
        # 3 legacy meta entry (eski format simülasyon)
        with writable_db._env.begin(db=writable_db._db_symbols, write=True) as txn:
            txn.put(b"__meta__:source_hash", b"legacy_hash")
            txn.put(b"__meta__:build_time", b"legacy_time")
            txn.put(b"__meta__:other_legacy", b"legacy_value")

        s = writable_db.stats()
        assert s.symbols == 2, (
            f"Legacy __meta__: entry'leri sayildi: {s.symbols} (beklenen 2). "
            "C4 fix: stats() __meta__: prefix'ini atlamali."
        )


class TestMaxDbsExpanded:
    """_DB_META eklenmesi -> max_dbs >= 5 olmali, aksi halde open_db hatasi."""

    def test_meta_db_opens_successfully(self, writable_db):
        """Write modunda _db_meta handle olmali ve calismali."""
        assert writable_db._db_meta is not None, (
            "_db_meta None -- LMDB max_dbs yeterli degil."
        )

    def test_all_five_dbs_accessible(self, writable_db):
        """5 named DB'nin hepsi acilmali (symbols, str, call, byte, meta)."""
        # Her DB'ye 1 entry yaz, sonra oku
        writable_db.bulk_write_symbols([
            ("_x", {"lib": "y", "purpose": "", "category": ""}),
        ])
        writable_db.bulk_write_string_sigs([
            (frozenset(["hello"]), ("greet", "lib", "say hi")),
        ])
        writable_db.bulk_write_call_sigs([
            (frozenset(["malloc"]), ("alloc_wrap", "libc", "wrapper", 0.9)),
        ])
        writable_db.bulk_write_byte_sigs([
            {"name": "test", "library": "testlib",
             "byte_pattern_hex": "aabbccdd", "byte_mask_hex": "ffffffff",
             "purpose": "", "category": ""},
        ])
        writable_db.put_metadata("my_key", b"my_val")

        s = writable_db.stats()
        assert s.symbols == 1
        assert s.string_sigs == 1
        assert s.call_sigs == 1
        assert s.byte_sigs == 1
        # Metadata sayilmamali
        assert writable_db.get_metadata("my_key") == b"my_val"
