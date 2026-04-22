"""v1.10.0 C1: LMDB uzun sembol ismi yazma/okuma regression testleri.

Onceki versiyonda ``bulk_write_symbols`` icindeki kontrol
``len(key) > len(name.encode("utf-8"))`` her zaman False idi (hashlenen key
18 byte, uzun isim 500+ byte). Bu yuzden ``_long_name`` payload'a HIC
eklenmiyordu ve uzun C++ mangled isimler lookup'ta collision korumasi
olmadan doner (teoride) veya bozuk payload uretir.

Fix: ``if key.startswith(_LONG_KEY_PREFIX):`` kontrolu.

Bu modul yeni testler:
  * Yazma sonrasi `_long_name` payload'da var mi?
  * lookup_symbol uzun ismi dogru geri dondurur mu?
  * Short name payload'i ``_long_name`` IÇERMEZ (gereksiz sisme onleme).
  * Hash collision durumunda lookup None doner (negative test).
"""

from __future__ import annotations

import pytest

lmdb = pytest.importorskip("lmdb")
msgpack = pytest.importorskip("msgpack")

from karadul.analyzers.sigdb_lmdb import (  # noqa: E402
    LMDBSignatureDB,
    _LONG_KEY_PREFIX,
    _MAX_SYMBOL_KEY_LEN,
    _symbol_key,
)


# ---------------------------------------------------------------------------
# Sabitler -- magic number yok, mantikli degerler
# ---------------------------------------------------------------------------

# C++ mangled isimler 600+ byte olabilir (template + namespace zinciri).
# Testte deterministik olmasi icin bu boyutlari kullaniyoruz.
_LONG_NAME_BYTES = 600          # > _MAX_SYMBOL_KEY_LEN (500)
_SHORT_NAME_SAMPLE = "_malloc"   # < 500 byte


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def writable_db(tmp_path):
    db = LMDBSignatureDB(tmp_path / "test.lmdb", readonly=False,
                         map_size=32 * 1024 * 1024)
    yield db
    db.close()


@pytest.fixture
def long_name():
    """600+ byte deterministik mock isim (C++ mangled'a benzer)."""
    # "_ZN3std7__cxx11" (15 byte) + "Templated" (9 byte) * 70 = 645 byte.
    base = "_ZN3std7__cxx11" + "Templated" * 70
    assert len(base.encode("utf-8")) >= _LONG_NAME_BYTES
    return base


# ---------------------------------------------------------------------------
# Testler
# ---------------------------------------------------------------------------


class TestLongNameWriteLookupRoundtrip:
    """C1 core fix: uzun isim yazma -> payload'da _long_name -> lookup geri oku."""

    def test_long_name_gets_long_name_payload(self, writable_db, long_name):
        """600 byte isim yazildiginda payload'a _long_name eklenmeli."""
        info = {"lib": "stl", "purpose": "alloc", "category": "mem"}
        count = writable_db.bulk_write_symbols([(long_name, info)])
        assert count == 1

        # Lookup -> payload'da _long_name var
        retrieved = writable_db.lookup_symbol(long_name)
        assert retrieved is not None, (
            "Uzun isim lookup miss -- _long_name yazilmadi mi?"
        )
        assert retrieved.get("_long_name") == long_name, (
            "Payload'a _long_name eklenmedi (C1 bug: eski len() karsilastirmasi "
            "her zaman False idi)."
        )
        # Original info korunmus
        assert retrieved["lib"] == "stl"
        assert retrieved["purpose"] == "alloc"

    def test_short_name_has_no_long_name_in_payload(self, writable_db):
        """Kisa isim (<500 byte) payload'inda _long_name OLMAMALI."""
        info = {"lib": "libc", "purpose": "alloc", "category": "memory"}
        writable_db.bulk_write_symbols([(_SHORT_NAME_SAMPLE, info)])

        retrieved = writable_db.lookup_symbol(_SHORT_NAME_SAMPLE)
        assert retrieved is not None
        assert "_long_name" not in retrieved, (
            "Short name'e gereksiz _long_name eklendi -- boyut sisirme."
        )

    def test_long_name_key_uses_long_prefix(self, long_name):
        """_symbol_key cikisinda _LONG_KEY_PREFIX olmali."""
        key = _symbol_key(long_name)
        assert key.startswith(_LONG_KEY_PREFIX), (
            f"Uzun isim icin _LONG_KEY_PREFIX kullanilmiyor. Key: {key[:20]!r}"
        )
        # 18 byte: prefix (2) + hash (16)
        assert len(key) == len(_LONG_KEY_PREFIX) + 16

    def test_short_name_key_is_direct_utf8(self):
        """Kisa isim raw utf-8 encoding kullanir, prefix'sizdir."""
        key = _symbol_key(_SHORT_NAME_SAMPLE)
        assert key == _SHORT_NAME_SAMPLE.encode("utf-8")
        assert not key.startswith(_LONG_KEY_PREFIX)


class TestLongNameBoundary:
    """_MAX_SYMBOL_KEY_LEN sinir degerleri: hashlenmeli vs hashlenmemeli."""

    def test_exactly_at_boundary_no_hash(self, writable_db):
        """len == _MAX_SYMBOL_KEY_LEN -> direkt utf-8 (<=_MAX)."""
        name = "a" * _MAX_SYMBOL_KEY_LEN
        writable_db.bulk_write_symbols([(name, {"lib": "x", "purpose": "y", "category": "z"})])
        retrieved = writable_db.lookup_symbol(name)
        assert retrieved is not None
        assert "_long_name" not in retrieved

    def test_one_byte_over_boundary_hashed(self, writable_db):
        """len == _MAX_SYMBOL_KEY_LEN + 1 -> hashlenir, _long_name yazilir."""
        name = "b" * (_MAX_SYMBOL_KEY_LEN + 1)
        writable_db.bulk_write_symbols([(name, {"lib": "x", "purpose": "y", "category": "z"})])
        retrieved = writable_db.lookup_symbol(name)
        assert retrieved is not None, "Sinir +1 byte'ta C1 fix calismiyor"
        assert retrieved.get("_long_name") == name


class TestLongNameCollisionGuard:
    """_long_name dogrulama yok -> hash collision icin miss don."""

    def test_direct_put_with_wrong_long_name_returns_miss(self, writable_db, long_name):
        """Dogrudan bozuk payload koy, lookup None dondurmeli (collision koruma)."""
        # Normalde bulk_write_symbols ile yazilir ve _long_name dogrudur.
        # Burada manual olarak YANLIS _long_name ile payload enjekte ediyoruz
        # -- bu hash collision / corrupted data simulasyonu.
        fake_payload = {"lib": "evil", "purpose": "x", "category": "y",
                        "_long_name": long_name + "_DIFFERENT_NAME"}
        key = _symbol_key(long_name)
        with writable_db._env.begin(db=writable_db._db_symbols, write=True) as txn:
            from karadul.analyzers.sigdb_lmdb import pack
            txn.put(key, pack(fake_payload))

        result = writable_db.lookup_symbol(long_name)
        # _long_name != name -> miss (C1 collision korumasi)
        assert result is None, (
            "Hash collision korumasi calismiyor -- _long_name dogrulamasi yok."
        )
