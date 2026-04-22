"""Unit testler: karadul.analyzers.sigdb_lmdb (v1.10.0 M1 T1).

LMDB-backed signature database'in izole testleri. Hepsi ``tmp_path`` ile
mini LMDB kurar, production LMDB'ye dokunmaz. Bu sayede CI'da kaynak
dosyalara bagimli degil, hizli calisir.
"""

from __future__ import annotations

import pytest

# LMDB opsiyonel bagimlilik -- yoksa tum test dosyasi skip
lmdb = pytest.importorskip("lmdb")
msgpack = pytest.importorskip("msgpack")

from karadul.analyzers.sigdb_lmdb import (  # noqa: E402
    BYTE_KEY_LEN,
    CANONICAL_HASH_LEN,
    DEFAULT_MAP_SIZE,
    LMDBSignatureDB,
    LMDBNotAvailableError,
    byte_prefix_key,
    canonical_call_key,
    canonical_string_key,
    default_lmdb_path,
    is_lmdb_available,
    pack,
    unpack,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def lmdb_path(tmp_path):
    """Temiz bir LMDB dizin yolu."""
    return tmp_path / "test.lmdb"


@pytest.fixture
def writable_db(lmdb_path):
    """Write-mode LMDB DB. Otomatik close."""
    db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=64 * 1024 * 1024)
    yield db
    if not db._closed:
        db.close()


@pytest.fixture
def populated_db(lmdb_path):
    """Icinde bir kac entry olan write-sonrasi-readonly DB."""
    # Once yazma modunda doldur
    w = LMDBSignatureDB(lmdb_path, readonly=False, map_size=64 * 1024 * 1024)
    w.bulk_write_symbols([
        ("_OPENSSL_init_crypto", {"lib": "openssl", "purpose": "init", "category": "crypto"}),
        ("_EVP_EncryptInit_ex", {"lib": "openssl", "purpose": "aes init", "category": "crypto"}),
        ("malloc", {"lib": "libc", "purpose": "alloc", "category": "memory"}),
    ])
    w.bulk_write_string_sigs([
        (frozenset(["hello", "world"]), ("greet_func", "testlib", "say hello")),
        (frozenset(["aes", "cbc", "encrypt"]), ("aes_encrypt", "testlib", "aes cbc mode")),
    ])
    w.bulk_write_call_sigs([
        (frozenset(["malloc", "memcpy", "free"]), ("copy_buf", "libc", "buffer copy", 0.85)),
    ])
    w.bulk_write_byte_sigs([
        {
            "name": "aes_sbox",
            "library": "crypto_constants",
            "byte_pattern_hex": "63 7c 77 7b f2 6b 6f c5".replace(" ", ""),
            "byte_mask_hex": "ff ff ff ff ff ff ff ff".replace(" ", ""),
            "category": "crypto",
            "purpose": "AES S-Box first row",
        },
        {
            "name": "sha256_k0",
            "library": "crypto_constants",
            "byte_pattern_hex": "428a2f98 71374491 b5c0fbcf".replace(" ", ""),
            "byte_mask_hex": "ffffffff ffffffff ffffffff".replace(" ", ""),
            "category": "crypto",
            "purpose": "SHA-256 K constants",
        },
    ])
    w.sync()
    w.close()

    # Readonly olarak tekrar ac
    db = LMDBSignatureDB(lmdb_path, readonly=True)
    yield db
    if not db._closed:
        db.close()


# ---------------------------------------------------------------------------
# Test 1: Create + open
# ---------------------------------------------------------------------------


class TestLMDBCreateAndOpen:
    def test_lmdb_create_and_open(self, lmdb_path):
        """Yazma modunda olusturulur, readonly ile tekrar acilabilir."""
        assert not lmdb_path.exists()

        # Yazma modu -> olusturulur
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=32 * 1024 * 1024)
        assert lmdb_path.exists()
        assert lmdb_path.is_dir()
        assert (lmdb_path / "data.mdb").exists()
        db.close()

        # Readonly -> tekrar acilir
        db2 = LMDBSignatureDB(lmdb_path, readonly=True)
        assert db2.readonly is True
        assert db2.path == lmdb_path.resolve()
        db2.close()

    def test_readonly_open_nonexistent_raises(self, tmp_path):
        """Readonly modda var olmayan path FileNotFoundError atmali."""
        with pytest.raises(FileNotFoundError):
            LMDBSignatureDB(tmp_path / "nonexistent.lmdb", readonly=True)


# ---------------------------------------------------------------------------
# Test 2: Symbol lookup hit
# ---------------------------------------------------------------------------


class TestSymbolLookup:
    def test_symbol_lookup_hit(self, populated_db):
        info = populated_db.lookup_symbol("_OPENSSL_init_crypto")
        assert info is not None
        assert info["lib"] == "openssl"
        assert info["purpose"] == "init"
        assert info["category"] == "crypto"

    def test_symbol_lookup_miss(self, populated_db):
        info = populated_db.lookup_symbol("this_does_not_exist_xyz")
        assert info is None

    def test_symbol_lookup_empty_name(self, populated_db):
        # Bos isim None donmeli (L1 cache'e girmemeli)
        assert populated_db.lookup_symbol("") is None


# ---------------------------------------------------------------------------
# Test 3: String signature canonical hash
# ---------------------------------------------------------------------------


class TestCanonicalHash:
    def test_string_sig_canonical_hash(self):
        """Ayni set, farkli siralama -> ayni key."""
        k1 = canonical_string_key({"a", "b", "c"})
        k2 = canonical_string_key(["c", "b", "a"])
        k3 = canonical_string_key(frozenset(["b", "a", "c"]))
        assert k1 == k2 == k3
        assert len(k1) == CANONICAL_HASH_LEN

    def test_call_key_canonical(self):
        k1 = canonical_call_key({"malloc", "free"})
        k2 = canonical_call_key(["free", "malloc"])
        assert k1 == k2

    def test_different_sets_different_keys(self):
        k1 = canonical_string_key({"a", "b"})
        k2 = canonical_string_key({"a", "c"})
        assert k1 != k2


class TestStringSigLookup:
    def test_string_sig_lookup_hit(self, populated_db):
        result = populated_db.lookup_string_sig({"hello", "world"})
        assert result is not None
        assert result == ("greet_func", "testlib", "say hello")

    def test_string_sig_lookup_order_independent(self, populated_db):
        r1 = populated_db.lookup_string_sig(["hello", "world"])
        r2 = populated_db.lookup_string_sig(["world", "hello"])
        assert r1 == r2

    def test_string_sig_lookup_miss(self, populated_db):
        assert populated_db.lookup_string_sig({"nope", "miss"}) is None


# ---------------------------------------------------------------------------
# Test 5: Call sig lookup
# ---------------------------------------------------------------------------


class TestCallSigLookup:
    def test_call_sig_lookup(self, populated_db):
        result = populated_db.lookup_call_sig({"malloc", "memcpy", "free"})
        assert result is not None
        name, lib, purpose, conf = result
        assert name == "copy_buf"
        assert lib == "libc"
        assert abs(conf - 0.85) < 1e-6

    def test_call_sig_miss(self, populated_db):
        assert populated_db.lookup_call_sig({"xyz"}) is None


# ---------------------------------------------------------------------------
# Test 6: Byte prefix range scan
# ---------------------------------------------------------------------------


class TestBytePrefixScan:
    def test_byte_prefix_range_scan(self, populated_db):
        # "63 7c 77 7b" ile baslayan aes_sbox
        prefix = bytes.fromhex("637c777b")
        results = populated_db.match_byte_prefix(prefix)
        assert len(results) >= 1
        names = [r.get("name") for r in results]
        assert "aes_sbox" in names

    def test_byte_prefix_no_match(self, populated_db):
        # Hicbir entry ile baslamayan prefix
        prefix = bytes.fromhex("deadbeefdeadbeef")
        results = populated_db.match_byte_prefix(prefix)
        assert results == []

    def test_byte_prefix_empty_returns_empty(self, populated_db):
        assert populated_db.match_byte_prefix(b"") == []

    def test_byte_prefix_key_padding(self):
        """Pattern 8'den kisa -> zero-padded."""
        k = byte_prefix_key(b"\x01\x02\x03")
        assert len(k) == BYTE_KEY_LEN
        assert k == b"\x01\x02\x03\x00\x00\x00\x00\x00"

    def test_byte_prefix_key_truncation(self):
        """Pattern 8'den uzun -> truncated."""
        k = byte_prefix_key(b"\xaa" * 20)
        assert len(k) == BYTE_KEY_LEN
        assert k == b"\xaa" * 8


# ---------------------------------------------------------------------------
# Test 7: L1 cache hit
# ---------------------------------------------------------------------------


class TestL1Cache:
    def test_l1_cache_hit(self, populated_db):
        # Ilk arama -> miss + disk read
        populated_db.lookup_symbol("_OPENSSL_init_crypto")
        stats1 = populated_db.cache_stats
        assert stats1["hits"] == 0
        assert stats1["misses"] == 1

        # Ayni arama -> hit
        populated_db.lookup_symbol("_OPENSSL_init_crypto")
        stats2 = populated_db.cache_stats
        assert stats2["hits"] == 1
        assert stats2["misses"] == 1  # artmamali

    def test_l1_cache_size_limit(self, tmp_path):
        """Kucuk cache size'da LRU eviction calisir."""
        p = tmp_path / "small.lmdb"
        w = LMDBSignatureDB(p, readonly=False, map_size=16 * 1024 * 1024)
        items = [(f"sym_{i}", {"lib": "x", "purpose": "", "category": "test"})
                 for i in range(100)]
        w.bulk_write_symbols(items)
        w.sync()
        w.close()

        db = LMDBSignatureDB(p, readonly=True, l1_cache_size=10)
        # 20 farkli sembol -> cache sadece son 10'u tutmali
        for i in range(20):
            db.lookup_symbol(f"sym_{i}")
        assert len(db._cache) == 10
        # Ilk sembol artik cache'te olmamali (evict edildi)
        # 20 lookup sonrasi cache'te sym_10..sym_19 var
        db.close()


# ---------------------------------------------------------------------------
# Test 8: Readonly write raises
# ---------------------------------------------------------------------------


class TestReadonlyWriteProtection:
    def test_readonly_write_raises(self, populated_db):
        """Readonly DB'ye yazma -> RuntimeError."""
        with pytest.raises(RuntimeError, match="readonly"):
            populated_db.bulk_write_symbols([("x", {"lib": "y", "purpose": "", "category": ""})])

    def test_readonly_put_metadata_raises(self, populated_db):
        with pytest.raises(RuntimeError, match="readonly"):
            populated_db.put_metadata("k", b"v")


# ---------------------------------------------------------------------------
# Test 9: Build script idempotent
# ---------------------------------------------------------------------------


class TestBuildScriptIdempotent:
    """scripts/build_sig_lmdb.py'i izole olarak test et (mini proje root)."""

    def test_build_script_idempotent(self, tmp_path, monkeypatch):
        """Ayni kaynak + ayni hash -> skip."""
        # Mini proje root: tek JSON kaynak
        project_root = tmp_path / "proj"
        project_root.mkdir()
        src = project_root / "signatures_mini.json"
        # v1.10.0 H5: build_sig_lmdb <100 byte dosyalari bos kabul edip
        # atliyor; test kaynagini gercek entry ile >=100 byte yap.
        src.write_text(
            '{"signatures": {'
            '"_foo": {"lib": "foo_lib", "purpose": "p", "category": "c"},'
            '"_bar": {"lib": "bar_lib", "purpose": "p", "category": "c"}'
            '}}',
            encoding="utf-8",
        )

        import importlib.util
        import sys as _sys
        spec = importlib.util.spec_from_file_location(
            "build_sig_lmdb",
            "/Users/apple/Desktop/black-widow/scripts/build_sig_lmdb.py",
        )
        mod = importlib.util.module_from_spec(spec)
        _sys.modules["build_sig_lmdb"] = mod
        spec.loader.exec_module(mod)

        output = tmp_path / "sig.lmdb"

        # Ilk build -> built
        r1 = mod.build(project_root=project_root, output=output, rebuild=False,
                       map_size=16 * 1024 * 1024)
        assert r1["status"] == "built"
        assert r1["symbols"] == 2
        first_hash = r1["hash"]

        # Ikinci build -> skip (hash ayni)
        r2 = mod.build(project_root=project_root, output=output, rebuild=False,
                       map_size=16 * 1024 * 1024)
        assert r2["status"] == "skip_uptodate"
        assert r2["hash"] == first_hash

        # Rebuild flag -> tekrar build
        r3 = mod.build(project_root=project_root, output=output, rebuild=True,
                       map_size=16 * 1024 * 1024)
        assert r3["status"] == "built"


# ---------------------------------------------------------------------------
# Test 10: total_entries
# ---------------------------------------------------------------------------


class TestTotalEntries:
    def test_total_entries(self, populated_db):
        entries = populated_db.total_entries
        assert entries["symbols"] >= 3
        # +meta entries (source_hash vb.) olabilir ama test DB'de yazmadik
        assert entries["string_sigs"] == 2
        assert entries["call_sigs"] == 1
        assert entries["byte_sigs"] == 2

    def test_stats_dataclass(self, populated_db):
        s = populated_db.stats()
        assert s.total == s.symbols + s.string_sigs + s.call_sigs + s.byte_sigs


# ---------------------------------------------------------------------------
# Test 11: Close releases env
# ---------------------------------------------------------------------------


class TestCloseReleasesEnv:
    def test_close_releases_env(self, lmdb_path):
        db = LMDBSignatureDB(lmdb_path, readonly=False, map_size=16 * 1024 * 1024)
        db.bulk_write_symbols([("x", {"lib": "a", "purpose": "", "category": "c"})])
        db.close()
        assert db._closed is True

        # Close sonrasi islem -> RuntimeError
        with pytest.raises(RuntimeError, match="closed"):
            db.lookup_symbol("x")

        # Idempotent close
        db.close()  # raise etmemeli

    def test_context_manager(self, lmdb_path):
        """``with`` cikisinda otomatik close."""
        with LMDBSignatureDB(lmdb_path, readonly=False, map_size=16 * 1024 * 1024) as db:
            assert not db._closed
        assert db._closed is True


# ---------------------------------------------------------------------------
# Test 12: Adapter feature flag routing
# ---------------------------------------------------------------------------


class TestAdapterFeatureFlag:
    """``SignatureDB`` adapter katmani LMDB flag'ine gore dogru yola gidiyor mu?"""

    def test_adapter_feature_flag_false_uses_dict(self):
        """use_lmdb_sigdb=False -> eski dict yolu, _lmdb_backend=None.

        v1.12.0 Faz 1: default True oldugu icin bu test acikca False'a
        cekmek zorunda. Onceden ``assert cfg.perf.use_lmdb_sigdb is False``
        idi; default degisikligi sonrasi explicit override gerekiyor.
        """
        from karadul.analyzers.signature_db import SignatureDB
        from karadul.config import Config

        cfg = Config()
        cfg.perf.use_lmdb_sigdb = False  # v1.12.0: default True, burada override
        db = SignatureDB(cfg)
        assert db._lmdb_backend is None
        # Dict DB doldurulmali (builtin en az birkac bin sembol icerir)
        assert len(db._symbol_db) > 100

    def test_adapter_feature_flag_true_uses_lmdb(self, tmp_path):
        """use_lmdb_sigdb=True + valid LMDB -> LMDB backend aktif."""
        from karadul.analyzers.signature_db import SignatureDB
        from karadul.config import Config

        # Mini LMDB hazirla
        lmdb_dir = tmp_path / "test_adapter.lmdb"
        w = LMDBSignatureDB(lmdb_dir, readonly=False, map_size=16 * 1024 * 1024)
        w.bulk_write_symbols([
            ("_my_custom_func", {"lib": "mylib", "purpose": "test", "category": "custom"}),
        ])
        w.sync()
        w.close()

        cfg = Config()
        cfg.perf.use_lmdb_sigdb = True
        cfg.perf.sig_lmdb_path = lmdb_dir

        db = SignatureDB(cfg)
        assert db._lmdb_backend is not None

        # LMDB'deki custom sembol builtin'de yok -- sadece LMDB'den bulunabilir
        match = db._match_by_symbol("_my_custom_func")
        assert match is not None
        assert match.library == "mylib"
        assert match.category == "custom"

        # Cleanup: LMDB backend'i kapat ki fixture silebilsin
        if db._lmdb_backend is not None:
            db._lmdb_backend.close()

    def test_adapter_feature_flag_true_missing_lmdb_fallback(self, tmp_path):
        """use_lmdb_sigdb=True ama LMDB yok -> graceful fallback (warning + dict)."""
        from karadul.analyzers.signature_db import SignatureDB
        from karadul.config import Config

        cfg = Config()
        cfg.perf.use_lmdb_sigdb = True
        cfg.perf.sig_lmdb_path = tmp_path / "nonexistent.lmdb"

        # Hata atmamali, None backend + dict dolu olmali
        db = SignatureDB(cfg)
        assert db._lmdb_backend is None
        assert len(db._symbol_db) > 100


# ---------------------------------------------------------------------------
# Ek: msgpack codec sanity
# ---------------------------------------------------------------------------


class TestMsgpackCodec:
    def test_pack_unpack_roundtrip(self):
        obj = {"lib": "openssl", "purpose": "init", "params": ["ctx", "flags"]}
        data = pack(obj)
        assert isinstance(data, bytes)
        assert unpack(data) == obj

    def test_pack_unicode(self):
        # Turkce karakterler utf-8 korunmali
        obj = {"purpose": "sifreleme fonksiyonu"}
        assert unpack(pack(obj)) == obj


# ---------------------------------------------------------------------------
# Ek: is_lmdb_available + default_path
# ---------------------------------------------------------------------------


def test_is_lmdb_available_true():
    assert is_lmdb_available() is True


def test_default_lmdb_path_home():
    p = default_lmdb_path()
    assert p.name == "signatures.lmdb"
    assert p.parent.name == ".karadul"
