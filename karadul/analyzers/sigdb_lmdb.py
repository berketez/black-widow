"""LMDB-backed signature database (v1.10.0 M1 T1).

Mevcut ``SignatureDB`` (``signature_db.py``) ~8.8M signature'i class-level
dict'lerde tutuyor ve ~3GB RAM kaplıyor. Bu modül LMDB (Lightning Memory-Mapped
Database) ile alternatif bir arka uç sağlar: zero-copy mmap, <250MB RSS,
cold-start <50ms.

Mimari
------

Tek LMDB environment, dört named database:

* ``symbols``     — key: symbol_name (utf-8), val: msgpack({lib, purpose, category, params})
* ``string_sigs`` — key: blake2b(sorted_strings)[:16], val: msgpack((lib, func, purpose))
* ``call_sigs``   — key: blake2b(sorted_api_calls)[:16], val: msgpack((lib, func, purpose, confidence))
* ``byte_sigs``   — key: first_bytes[:8] (bytes), val: msgpack(FunctionSignature dict)

Prefix araması ``set_range`` cursor ile yapılır.

Iki katmanlı cache:

* L1: OrderedDict LRU (varsayılan 8192 entry) — sıcak sembol lookup
* L2: LMDB mmap — OS page cache (serbest RAM kadar)

Public API
----------

``LMDBSignatureDB`` sınıfı. ``SignatureDB`` ile birebir aynı arayüz
*değildir*; adapter katmanı ``signature_db.SignatureDB`` içinde yapılır.

Build
-----

LMDB'yi üretmek için ``scripts/build_sig_lmdb.py`` kullanılır (idempotent,
version hash ile kaynak değişikliği algılar).

Notlar
------

* ``blake3`` varsa kullanılır (hızlı); yoksa ``hashlib.blake2b`` fallback.
* ``msgpack`` zorunlu bağımlılık.
* ``lmdb`` binding C seviyesinde, GIL-free.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

import msgpack

# blake3 opsiyonel (hızlı), yoksa hashlib.blake2b fallback
try:
    import blake3 as _blake3  # type: ignore[import]

    def _fast_hash(data: bytes, digest_size: int = 16) -> bytes:
        # blake3 32 byte dondurur; istenen boyuta truncate
        return _blake3.blake3(data).digest(length=digest_size)

except ImportError:
    _blake3 = None  # type: ignore[assignment]

    def _fast_hash(data: bytes, digest_size: int = 16) -> bytes:
        return hashlib.blake2b(data, digest_size=digest_size).digest()


# lmdb bagimliligi opsiyonel (graceful degradation)
try:
    import lmdb  # type: ignore[import]
    _LMDB_AVAILABLE = True
except ImportError:
    lmdb = None  # type: ignore[assignment]
    _LMDB_AVAILABLE = False


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

# LMDB named DB isimleri
_DB_SYMBOLS = b"symbols"
_DB_STRING_SIGS = b"string_sigs"
_DB_CALL_SIGS = b"call_sigs"
_DB_BYTE_SIGS = b"byte_sigs"
# v1.10.0 C4: Metadata icin ayri named DB.
# Onceki versiyonlarda metadata symbols DB'ye ``__meta__:`` prefix ile
# yazilirdi -> ``stats()`` gercek sembol sayisini fazla gosteriyordu ve
# iterasyon meta entry'leri gorecekti. Artik izole.
_DB_META = b"meta"

_ALL_DBS = (_DB_SYMBOLS, _DB_STRING_SIGS, _DB_CALL_SIGS, _DB_BYTE_SIGS, _DB_META)

# Varsayilan map_size: 8 GiB (8M+ C++ mangled symbol hedefi).
# Readonly modda gercek on-disk boyut kullanilir, bu sadece upper bound.
# Build sirasinda yetersiz kalirsa script set_mapsize ile buyutur.
DEFAULT_MAP_SIZE = 8 * 1024 ** 3  # 8 GiB

# Default LMDB konumu (config.perf.sig_lmdb_path None ise)
_DEFAULT_LMDB_DIR = Path.home() / ".karadul" / "signatures.lmdb"

# Byte pattern key prefix uzunlugu (ilk 8 byte cursor set_range icin yeterli
# seviyede selective, daha uzun key false positive azaltir ama scan uzar).
BYTE_KEY_LEN = 8

# Canonical hash uzunlugu (bayt). 16 byte = 128 bit -> çakisma olasiligi
# 8M entry icin ~2^-89, pratik olarak sifir.
CANONICAL_HASH_LEN = 16


# ---------------------------------------------------------------------------
# Hata sinifi
# ---------------------------------------------------------------------------


class LMDBNotAvailableError(RuntimeError):
    """lmdb modulu yuklu degilken LMDBSignatureDB olusturulmaya calisildi."""


# ---------------------------------------------------------------------------
# Canonical hashing (deterministik set -> 16 byte key)
# ---------------------------------------------------------------------------


def canonical_string_key(strings: Iterable[str]) -> bytes:
    """String kumesi icin deterministik 16 byte key uret.

    {"a", "b"} ve {"b", "a"} ayni key'i uretmeli (frozenset sirasizligi).
    Ayirac olarak ``\\x1f`` (unit separator) kullanilir -- ascii printable
    disinda, string'lerde bulunmasi cok dusuk ihtimal.
    """
    canonical = "\x1f".join(sorted(strings)).encode("utf-8")
    return _fast_hash(canonical, digest_size=CANONICAL_HASH_LEN)


def canonical_call_key(apis: Iterable[str]) -> bytes:
    """API cagri kumesi icin deterministik 16 byte key.

    String key ile benzer algoritma; ayri fonksiyon tuttuk cunku ileride
    versiyon/prefix eklenmesi gerekebilir (ornegin "v2:" prefix).
    """
    canonical = "\x1f".join(sorted(apis)).encode("utf-8")
    return _fast_hash(canonical, digest_size=CANONICAL_HASH_LEN)


# LMDB default max key size = 511 bytes. C++ mangled isimler bu sinirin
# ustune cikabilir. Uzun isimleri hash'liyoruz, prefix ile collision
# short-name entry'lerden ayirt ediliyor.
_MAX_SYMBOL_KEY_LEN = 500  # Safe margin (511 limit'inden)
_LONG_KEY_PREFIX = b"H:"  # Hashed key marker (short name collision korumasi)


def _symbol_key(name: str) -> bytes:
    """Sembol adindan LMDB key uret.

    Kisa isim (<500 byte UTF-8) -> direkt utf-8 encoded.
    Uzun isim -> ``_LONG_KEY_PREFIX + blake2b(name)[:16]`` (18 byte).

    ``_LONG_KEY_PREFIX`` = "H:" -- gercek bir C++ identifier'in kolonla
    baslamasi mumkun olmadigi icin collision riski sifir.
    """
    encoded = name.encode("utf-8")
    if len(encoded) <= _MAX_SYMBOL_KEY_LEN:
        return encoded
    return _LONG_KEY_PREFIX + _fast_hash(encoded, digest_size=16)


def byte_prefix_key(pattern: bytes) -> bytes:
    """Byte pattern icin LMDB key: ilk ``BYTE_KEY_LEN`` byte.

    Pattern daha kisa ise zero-padding uygular (cursor range scan icin
    deterministik olmali).
    """
    if len(pattern) >= BYTE_KEY_LEN:
        return pattern[:BYTE_KEY_LEN]
    return pattern + b"\x00" * (BYTE_KEY_LEN - len(pattern))


# ---------------------------------------------------------------------------
# Simple LRU (OrderedDict tabanli)
# ---------------------------------------------------------------------------


class _LRUCache:
    """Basit thread-unsafe LRU cache.

    ``functools.lru_cache`` decorator'unun class-method'larda
    memory leak'lere yol acmasi nedeniyle explicit kullaniyoruz.
    Miss durumunda None donulur; caller LMDB'ye gitmek zorunda.
    """

    __slots__ = ("_cache", "_maxsize", "hits", "misses")

    def __init__(self, maxsize: int = 8192) -> None:
        if maxsize < 0:
            raise ValueError("maxsize negatif olamaz")
        self._cache: OrderedDict[Any, Any] = OrderedDict()
        self._maxsize = maxsize
        self.hits = 0
        self.misses = 0

    def get(self, key: Any) -> Any:
        if key in self._cache:
            self._cache.move_to_end(key)
            self.hits += 1
            return self._cache[key]
        self.misses += 1
        return None

    def put(self, key: Any, value: Any) -> None:
        if self._maxsize == 0:
            return
        if key in self._cache:
            self._cache.move_to_end(key)
            self._cache[key] = value
            return
        self._cache[key] = value
        if len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)

    def clear(self) -> None:
        self._cache.clear()
        self.hits = 0
        self.misses = 0

    def __len__(self) -> int:
        return len(self._cache)


# ---------------------------------------------------------------------------
# msgpack codec
# ---------------------------------------------------------------------------


def pack(obj: Any) -> bytes:
    """msgpack encode — ``use_bin_type=True``, bytes/str ayrimi korunur."""
    return msgpack.packb(obj, use_bin_type=True)


def unpack(data: bytes) -> Any:
    """msgpack decode — ``raw=False``, string'ler utf-8 cozulur."""
    return msgpack.unpackb(data, raw=False)


# ---------------------------------------------------------------------------
# LMDB-backed signature database
# ---------------------------------------------------------------------------


@dataclass
class LMDBStats:
    """LMDB DB boyut istatistikleri."""

    symbols: int
    string_sigs: int
    call_sigs: int
    byte_sigs: int

    @property
    def total(self) -> int:
        return self.symbols + self.string_sigs + self.call_sigs + self.byte_sigs


class LMDBSignatureDB:
    """LMDB-backed read-heavy signature database.

    Varsayilan ``readonly=True`` — build script (``scripts/build_sig_lmdb.py``)
    disinda yazma YAPILMAMALIDIR. Build script ``readonly=False`` ile bir
    ``LMDBSignatureDB`` acar, ``bulk_write_*`` helper'lari kullanir ve
    ``close()`` eder.

    Ornek
    -----

    >>> db = LMDBSignatureDB(Path("~/.karadul/signatures.lmdb").expanduser())
    >>> info = db.lookup_symbol("_OPENSSL_init_crypto")
    >>> info["lib"] if info else "miss"
    'openssl'

    Args
    ----
    lmdb_path:
        LMDB environment dizini (lmdb tek dosya degil, dizin; icinde
        ``data.mdb`` ve ``lock.mdb``).
    readonly:
        True ise read-only modda acilir (mmap copy-on-write engellenir,
        multi-reader guvenli).
    l1_cache_size:
        Symbol lookup LRU cache boyutu (varsayilan 8192).
    map_size:
        LMDB mmap boyutu. Readonly modda anlamsiz (mevcut ``data.mdb``
        boyutu kullanilir). Build sirasinda 2 GiB varsayilan.
    """

    __slots__ = (
        "_path",
        "_readonly",
        "_env",
        "_db_symbols",
        "_db_string_sigs",
        "_db_call_sigs",
        "_db_byte_sigs",
        "_db_meta",
        "_cache",
        "_closed",
    )

    def __init__(
        self,
        lmdb_path: Path,
        *,
        readonly: bool = True,
        l1_cache_size: int = 8192,
        map_size: int = DEFAULT_MAP_SIZE,
    ) -> None:
        if not _LMDB_AVAILABLE:
            raise LMDBNotAvailableError(
                "lmdb modulu yuklu degil. pip install lmdb msgpack"
            )

        self._path = Path(lmdb_path).expanduser().resolve()
        self._readonly = readonly
        self._closed = False
        self._cache = _LRUCache(maxsize=l1_cache_size)

        # Readonly modda path MEVCUT olmali.
        # Yazma modunda olusturulacak.
        if readonly and not self._path.exists():
            raise FileNotFoundError(
                f"LMDB bulunamadi: {self._path}. "
                "scripts/build_sig_lmdb.py ile olusturun."
            )

        if not readonly:
            self._path.mkdir(parents=True, exist_ok=True)

        # Environment ac
        # subdir=True: LMDB dizin olarak tutulur (data.mdb + lock.mdb)
        # max_dbs=4: 4 named database
        # readahead=False: buyuk DB icin OS read-ahead gereksiz, RAM tasarrufu
        self._env = lmdb.open(
            str(self._path),
            map_size=map_size,
            max_dbs=len(_ALL_DBS),
            readonly=readonly,
            subdir=True,
            readahead=False,
            # sync ve metasync readonly'da anlamsiz; yazma sirasinda
            # build script'te True bırakiyoruz (crash durumunda fsync guvenli).
            lock=True,
        )

        # Named DB handle'lari
        self._db_symbols = self._env.open_db(_DB_SYMBOLS, create=not readonly)
        self._db_string_sigs = self._env.open_db(_DB_STRING_SIGS, create=not readonly)
        self._db_call_sigs = self._env.open_db(_DB_CALL_SIGS, create=not readonly)
        self._db_byte_sigs = self._env.open_db(_DB_BYTE_SIGS, create=not readonly)
        # v1.10.0 C4: meta DB ayri tutulur (symbols'tan izole).
        # Readonly modda eski LMDB'lerde meta DB olmayabilir; create=False
        # halinde open_db KeyError verir -> graceful: None atiyoruz ve
        # get_metadata ``__meta__:`` fallback path'ine dusuyor.
        try:
            self._db_meta = self._env.open_db(_DB_META, create=not readonly)
        except lmdb.NotFoundError:  # type: ignore[attr-defined]
            # Readonly + eski LMDB -> meta DB yok. Symbols'daki __meta__:
            # prefix'i fallback olarak kullanilacak.
            self._db_meta = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> LMDBSignatureDB:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        # Best-effort cleanup. env.close() idempotent degil; closed guard.
        try:
            if not self._closed:
                self.close()
        except Exception:
            pass

    def close(self) -> None:
        """LMDB environment'i kapat, mmap'i serbest birak."""
        if self._closed:
            return
        try:
            self._env.close()
        finally:
            self._closed = True

    # ------------------------------------------------------------------
    # Readonly lookup API
    # ------------------------------------------------------------------

    def lookup_symbol(self, name: str) -> Optional[dict]:
        """Sembol isminden metadata sorgula.

        Returns
        -------
        ``{"lib": str, "purpose": str, "category": str, ...}`` veya None.
        """
        self._ensure_open()
        if not name:
            return None

        # L1 cache
        cached = self._cache.get(name)
        if cached is not None:
            # _LRUCache.get None'da miss; sentinel kullanmiyoruz
            # cunku None valid deger degil (yok -> None)
            return cached

        key = _symbol_key(name)
        with self._env.begin(db=self._db_symbols, buffers=True) as txn:
            raw = txn.get(key)
            if raw is None:
                return None
            # buffers=True -> memoryview; bytes kopyasi olmasin
            value = unpack(bytes(raw))

        # Uzun isim: payload'da _long_name ile dogrulama
        # (hash collision teorik olarak mumkun, pratikte sifir ama guvenlik)
        if key.startswith(_LONG_KEY_PREFIX):
            if value.get("_long_name") != name:
                # Hash collision veya bozuk veri -- miss say
                return None

        self._cache.put(name, value)
        return value

    def lookup_string_sig(self, strings: Iterable[str]) -> Optional[tuple]:
        """String kumesi imzasi sorgula.

        Args
        ----
        strings:
            Fonksiyonun referans verdigi string kumesi. Sira onemsiz
            (canonical hash kullanilir).

        Returns
        -------
        ``(matched_name, library, purpose)`` veya None.
        """
        self._ensure_open()
        key = canonical_string_key(strings)
        with self._env.begin(db=self._db_string_sigs, buffers=True) as txn:
            raw = txn.get(key)
            if raw is None:
                return None
            payload = unpack(bytes(raw))
        # payload: [matched_name, library, purpose]
        if isinstance(payload, list) and len(payload) == 3:
            return tuple(payload)
        return None

    def lookup_call_sig(self, apis: Iterable[str]) -> Optional[tuple]:
        """Cagri kumesi imzasi sorgula.

        Returns
        -------
        ``(matched_name, library, purpose, confidence)`` veya None.
        """
        self._ensure_open()
        key = canonical_call_key(apis)
        with self._env.begin(db=self._db_call_sigs, buffers=True) as txn:
            raw = txn.get(key)
            if raw is None:
                return None
            payload = unpack(bytes(raw))
        # payload: [matched_name, library, purpose, confidence]
        if isinstance(payload, list) and len(payload) == 4:
            return tuple(payload)
        return None

    def match_byte_prefix(self, prefix: bytes, max_results: int = 32) -> list[dict]:
        """Byte pattern prefix'inden eslesen FunctionSignature payload'larini dondur.

        Cursor.set_range kullanir: ``prefix`` ile baslayan tum entry'leri tarar.
        Pattern'in DB'deki ``byte_pattern`` ile tam uyumu caller tarafinda
        kontrol edilir (mask ile).

        Args
        ----
        prefix:
            En az 1 byte. 8 byte'a padded/truncated.
        max_results:
            En fazla kaç entry donulecek (DoS guvenligi).

        Returns
        -------
        ``list[dict]`` -- ``FunctionSignature`` payload'lari
        (name, library, version, byte_pattern_hex, byte_mask_hex, size_range, purpose, category).
        """
        self._ensure_open()
        if not prefix:
            return []

        search_key = byte_prefix_key(prefix)
        results: list[dict] = []

        with self._env.begin(db=self._db_byte_sigs, buffers=True) as txn:
            cursor = txn.cursor()
            if not cursor.set_range(search_key):
                return []
            for key, value in cursor:
                # Cursor prefix'i asti mi? LMDB anahtarlar lexicographic sirali.
                key_bytes = bytes(key)
                if not key_bytes.startswith(search_key[: len(prefix)]):
                    break
                try:
                    payload = unpack(bytes(value))
                except Exception:
                    logger.warning("Byte sig decode failed at key %r", key_bytes)
                    continue
                if isinstance(payload, dict):
                    results.append(payload)
                if len(results) >= max_results:
                    break
        return results

    # ------------------------------------------------------------------
    # Istatistik
    # ------------------------------------------------------------------

    @property
    def total_entries(self) -> dict[str, int]:
        """Her named DB icin entry sayisini dondur.

        Hizli: LMDB stat() syscall, iteration yok.
        """
        self._ensure_open()
        stats = self.stats()
        return {
            "symbols": stats.symbols,
            "string_sigs": stats.string_sigs,
            "call_sigs": stats.call_sigs,
            "byte_sigs": stats.byte_sigs,
        }

    def stats(self) -> LMDBStats:
        """Dataclass olarak istatistikler.

        v1.10.0 C4: Legacy LMDB'lerde symbols DB'sine yazilmis
        ``__meta__:`` prefix'li entry'ler gercek sembol degildir; cikart.
        Yeni LMDB'lerde ``_DB_META`` ayri oldugu icin s_sym temiz olur.
        """
        self._ensure_open()
        with self._env.begin() as txn:
            s_sym = txn.stat(self._db_symbols)
            s_str = txn.stat(self._db_string_sigs)
            s_call = txn.stat(self._db_call_sigs)
            s_byte = txn.stat(self._db_byte_sigs)
            # Legacy kirliligi say (1 pass cursor, kucuk overhead -- onbuku
            # tipik olarak < 10 entry)
            meta_pollution = 0
            with txn.cursor(db=self._db_symbols) as cur:
                if cur.set_range(b"__meta__:"):
                    for key, _ in cur:
                        if not bytes(key).startswith(b"__meta__:"):
                            break
                        meta_pollution += 1
        return LMDBStats(
            symbols=s_sym["entries"] - meta_pollution,
            string_sigs=s_str["entries"],
            call_sigs=s_call["entries"],
            byte_sigs=s_byte["entries"],
        )

    @property
    def cache_stats(self) -> dict[str, int]:
        return {
            "hits": self._cache.hits,
            "misses": self._cache.misses,
            "size": len(self._cache),
        }

    @property
    def path(self) -> Path:
        return self._path

    @property
    def readonly(self) -> bool:
        return self._readonly

    # ------------------------------------------------------------------
    # Bulk write API (sadece build script icin)
    # ------------------------------------------------------------------

    def bulk_write_symbols(self, items: Iterable[tuple[str, dict]]) -> int:
        """Symbol dict'lerini LMDB'ye yaz.

        Uzun C++ mangled isimler (>~500 byte) LMDB max key size'i asar;
        bunlar ``_LONG_KEY_PREFIX + blake2b(name)[:16]`` ile hash'lenir ve
        ``info["_long_name"]`` alaninda orijinal isim korunur.
        lookup_symbol da ayni stratejiye dusup hashed key arar.

        Args
        ----
        items:
            ``(name, {"lib": ..., "purpose": ..., "category": ..., ...})``
            tuple iterator'u.

        Returns
        -------
        Yazilan entry sayisi.
        """
        self._ensure_writable()
        count = 0
        # Tek transaction -> atomik + hizli (fsync bir kez)
        with self._env.begin(db=self._db_symbols, write=True) as txn:
            for name, info in items:
                if not name:
                    continue
                key = _symbol_key(name)
                # v1.10.0 C1 fix: _LONG_KEY_PREFIX ile prefix'li key,
                # isim >_MAX_SYMBOL_KEY_LEN byte oldugunda uretilir.
                # Onceki kontrol `len(key) > len(name.encode())` her zaman
                # False idi (hashli key 18 byte, isim 500+ byte) -- prefix
                # kontrolu kesin ve niyete uygun.
                if key.startswith(_LONG_KEY_PREFIX):
                    # Hash'lendi -- orijinal isim payload'da olmali
                    # (lookup_symbol'deki collision dogrulamasi icin)
                    payload = dict(info)
                    payload["_long_name"] = name
                    txn.put(key, pack(payload))
                else:
                    txn.put(key, pack(info))
                count += 1
        return count

    def bulk_write_string_sigs(
        self, items: Iterable[tuple[frozenset[str], tuple[str, str, str]]]
    ) -> int:
        """String signature'larini yaz.

        Args
        ----
        items:
            ``(frozenset_keywords, (matched_name, library, purpose))``.
        """
        self._ensure_writable()
        count = 0
        with self._env.begin(db=self._db_string_sigs, write=True) as txn:
            for keywords, payload in items:
                key = canonical_string_key(keywords)
                txn.put(key, pack(list(payload)))
                count += 1
        return count

    def bulk_write_call_sigs(
        self,
        items: Iterable[tuple[frozenset[str], tuple[str, str, str, float]]],
    ) -> int:
        """Call pattern signature'larini yaz.

        Args
        ----
        items:
            ``(frozenset_callees, (matched_name, library, purpose, confidence))``.
        """
        self._ensure_writable()
        count = 0
        with self._env.begin(db=self._db_call_sigs, write=True) as txn:
            for callees, payload in items:
                key = canonical_call_key(callees)
                txn.put(key, pack(list(payload)))
                count += 1
        return count

    def bulk_write_byte_sigs(self, items: Iterable[dict]) -> int:
        """Byte signature dict'lerini yaz.

        Args
        ----
        items:
            Her eleman {"name", "library", "byte_pattern_hex",
            "byte_mask_hex", ...} -- pattern hex string olarak tutulur
            (msgpack bytes tipiyle de olur ama JSON interop icin hex).

        Key: byte_prefix_key(bytes.fromhex(byte_pattern_hex)).
        Aynı prefix'e sahip birden fazla pattern olabilir; LMDB
        ``dupsort=False`` oldugu icin son yazan kazanir. Build script
        name-uniqueness garantisini disaridan saglamali.

        Alternatif: ``name:addr`` ile birlestirerek key yapmak.
        Burada name'i key'e eklemiyoruz cunku arama hizli prefix scan
        icin pattern bytes'inden baslamali. Caller set_range sonrasi
        mask kontrolu yapiyor.
        """
        self._ensure_writable()
        count = 0
        with self._env.begin(db=self._db_byte_sigs, write=True) as txn:
            for entry in items:
                pattern_hex = entry.get("byte_pattern_hex", "")
                if not pattern_hex:
                    continue
                try:
                    pattern_bytes = bytes.fromhex(pattern_hex)
                except ValueError:
                    logger.warning("Gecersiz hex pattern: %s", entry.get("name"))
                    continue
                # Pattern + name hash -> unique key (8 byte pattern prefix'i
                # uniqueness saglamaz, name ile augment)
                name = entry.get("name", "")
                name_hash = _fast_hash(name.encode("utf-8"), digest_size=4)
                key = byte_prefix_key(pattern_bytes) + name_hash
                txn.put(key, pack(entry))
                count += 1
        return count

    def put_metadata(self, meta_key: str, value: bytes) -> None:
        """Versiyon/meta kaydi yaz.

        v1.10.0 C4: Ayri ``_DB_META`` named DB kullanilir (onceden symbols
        DB'ye ``__meta__:`` prefix ile yazilirdi -> stats() ve iterasyon
        meta'yi kirletiyordu).

        Bu metadata ana lookup API'sinde goz onune alinmaz; sadece
        build script version hash'i gibi seyler icin.
        """
        self._ensure_writable()
        key = meta_key.encode("utf-8")
        if self._db_meta is not None:
            with self._env.begin(db=self._db_meta, write=True) as txn:
                txn.put(key, value)
        else:
            # Fallback (tipik olarak readonly modda calismaz ama
            # ensure_writable zaten readonly'de RuntimeError verir).
            legacy = f"__meta__:{meta_key}".encode("utf-8")
            with self._env.begin(db=self._db_symbols, write=True) as txn:
                txn.put(legacy, value)

    def get_metadata(self, meta_key: str) -> Optional[bytes]:
        self._ensure_open()
        key = meta_key.encode("utf-8")
        # v1.10.0 C4: Once yeni meta DB'den dene; eski LMDB'ler (meta DB
        # yok veya key bulunamadi) __meta__: prefix'li symbols'a dusmeli.
        if self._db_meta is not None:
            with self._env.begin(db=self._db_meta) as txn:
                raw = txn.get(key)
                if raw is not None:
                    return bytes(raw)
        legacy_key = f"__meta__:{meta_key}".encode("utf-8")
        with self._env.begin(db=self._db_symbols) as txn:
            raw = txn.get(legacy_key)
            return bytes(raw) if raw is not None else None

    def sync(self) -> None:
        """Pending yazmalari diske flush et."""
        self._ensure_writable()
        # lmdb 1.x: Environment.sync(force: bool) -- positional only
        self._env.sync(True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("LMDBSignatureDB closed")

    def _ensure_writable(self) -> None:
        self._ensure_open()
        if self._readonly:
            raise RuntimeError(
                "LMDBSignatureDB readonly modda. readonly=False ile yeniden acin."
            )


# ---------------------------------------------------------------------------
# Convenience fabrikalari
# ---------------------------------------------------------------------------


def default_lmdb_path() -> Path:
    """Varsayilan LMDB konumu: ~/.karadul/signatures.lmdb.

    ``KARADUL_SIG_LMDB_PATH`` env variable varsa onu kullanir.
    """
    env_path = os.environ.get("KARADUL_SIG_LMDB_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return _DEFAULT_LMDB_DIR


def is_lmdb_available() -> bool:
    """lmdb Python binding yuklu mu?"""
    return _LMDB_AVAILABLE


def open_readonly(path: Optional[Path] = None, **kwargs: Any) -> LMDBSignatureDB:
    """Readonly LMDBSignatureDB fabrika."""
    actual_path = path or default_lmdb_path()
    return LMDBSignatureDB(actual_path, readonly=True, **kwargs)


__all__ = [
    "LMDBSignatureDB",
    "LMDBStats",
    "LMDBNotAvailableError",
    "canonical_string_key",
    "canonical_call_key",
    "byte_prefix_key",
    "default_lmdb_path",
    "is_lmdb_available",
    "open_readonly",
    "pack",
    "unpack",
    "DEFAULT_MAP_SIZE",
    "BYTE_KEY_LEN",
    "CANONICAL_HASH_LEN",
]
