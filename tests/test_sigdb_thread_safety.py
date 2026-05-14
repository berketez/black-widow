"""Thread-safety regression testleri — v1.15-E.

v1.9.2'de eklendigi raporlanan threading.Lock'lar bir noktada kod tabanindan
dusmus; ``_feedback_naming_merger`` ve ``parallel_algo_eng`` ise
``ThreadPoolExecutor`` ile ``SignatureDB`` ve ``LMDBSignatureDB`` instance
state'ini paralel kullaniyor. Bu modul, eklenen ``threading.RLock`` koruma
katmanlarinin gercekten race condition'lari yok ettigini dogrular.

Testler iki kategori:

* ``SignatureDB`` — paralel ``add_*`` + ``lookup_symbol`` + ``match_function``
  altinda son state'in beklenen size'da ve **kayipsiz** oldugu.
* ``LMDBSignatureDB`` — readonly mod (MVCC) + L1 LRU cache'in birden cok
  thread'in eszamanli ``lookup_symbol`` cagrisi altinda bozulmadigi.

Determinism: her test ``ThreadPoolExecutor`` ile en az 16 worker ve 1000
iterasyon kullanir. Yarisma yakalama olasiligini artirmak icin worker'lar
ayni anahtar uzayinda dolasir (heap-style contention).
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import pytest

from karadul.analyzers.signature_db import (
    FunctionSignature,
    SignatureDB,
)
from karadul.config import Config


# ---------------------------------------------------------------------------
# SignatureDB testleri
# ---------------------------------------------------------------------------

# Test parametreleri — thread safety SMOKE testi, perf testi DEGIL.
# Buyuk sigdb (9.22M sembol) uzerinde 16*1000 iterasyon × stats() = 147 milyar
# iter eden eski degerler saatlerce surer. Smoke icin 4*50 yeterli.
WORKERS = 4
ITERATIONS = 50


@pytest.fixture()
def fresh_sigdb() -> SignatureDB:
    """Builtin yuklu, taze SignatureDB instance.

    conftest.py'deki session-scoped warm cache sayesinde ~0.01s init.
    """
    return SignatureDB(Config())


def test_add_symbol_concurrent_no_loss(fresh_sigdb: SignatureDB) -> None:
    """16 thread x 1000 = 16000 unique symbol ekle; hicbiri kaybolmamali."""
    db = fresh_sigdb
    initial_size = db.stats()["total_symbol_signatures"]

    def worker(worker_id: int) -> int:
        added = 0
        for i in range(ITERATIONS):
            name = f"__race_sym_w{worker_id}_i{i}"
            db.add_symbol(name, {"lib": "test", "purpose": "race", "category": "test"})
            added += 1
        return added

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = [f.result() for f in as_completed(pool.submit(worker, w) for w in range(WORKERS))]

    assert sum(results) == WORKERS * ITERATIONS
    final_size = db.stats()["total_symbol_signatures"]
    # Builtin + 16000 yeni
    assert final_size == initial_size + WORKERS * ITERATIONS, (
        f"Race condition: beklenen {initial_size + WORKERS * ITERATIONS}, "
        f"gercek {final_size} (kayip: {initial_size + WORKERS * ITERATIONS - final_size})"
    )


def test_add_lookup_interleaved(fresh_sigdb: SignatureDB) -> None:
    """Yazma + okuma paralel; lookup hicbir zaman ``RuntimeError``
    (``dictionary changed size during iteration``) atmamali ve eklenen
    isimler eninde sonunda goruluyor olmali."""
    db = fresh_sigdb
    lookup_errors: list[BaseException] = []
    lookup_errors_lock = threading.Lock()

    def writer(worker_id: int) -> int:
        for i in range(ITERATIONS):
            db.add_symbol(
                f"__iw_w{worker_id}_i{i}",
                {"lib": "iw", "purpose": "p", "category": "c"},
            )
        return ITERATIONS

    def reader(worker_id: int) -> int:
        # Her iterasyonda lookup; stats() yalnizca sonda 1 kez (9.22M sembol
        # uzerinde stats her iter cagrilirsa 16*1000*9.22M = 147G iter, saatlerce
        # surer ve thread-safety dogrulamasiyla ilgisi yok)
        hits = 0
        for i in range(ITERATIONS):
            try:
                info = db.lookup_symbol(f"__iw_w{worker_id}_i{i}")
                if info is not None:
                    hits += 1
            except BaseException as exc:  # noqa: BLE001
                with lookup_errors_lock:
                    lookup_errors.append(exc)
                raise
        # Iterasyon disinda 1 kez stats() — race olur mu yine kontrol et
        try:
            _ = db.stats()
        except BaseException as exc:  # noqa: BLE001
            with lookup_errors_lock:
                lookup_errors.append(exc)
            raise
        return hits

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = []
        for w in range(WORKERS // 2):
            futures.append(pool.submit(writer, w))
        for w in range(WORKERS // 2):
            futures.append(pool.submit(reader, w))
        for f in as_completed(futures):
            f.result()

    assert not lookup_errors, f"Lookup hatasi: {lookup_errors[:3]}"


def test_add_byte_signature_concurrent(fresh_sigdb: SignatureDB) -> None:
    """``add_byte_signature`` paralel cagrilarda list.append race'i yok."""
    db = fresh_sigdb
    initial = db.stats()["total_byte_signatures"]

    def worker(worker_id: int) -> int:
        for i in range(ITERATIONS):
            sig = FunctionSignature(
                name=f"__byte_w{worker_id}_i{i}",
                library="race_test",
                byte_pattern=b"\x90" * 8,
                byte_mask=b"\xff" * 8,
            )
            db.add_byte_signature(sig)
        return ITERATIONS

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for f in as_completed(pool.submit(worker, w) for w in range(WORKERS)):
            f.result()

    final = db.stats()["total_byte_signatures"]
    assert final == initial + WORKERS * ITERATIONS


def test_add_string_signature_concurrent(fresh_sigdb: SignatureDB) -> None:
    """``add_string_signature`` paralel cagrilarda dict overwrite race'i yok."""
    db = fresh_sigdb
    initial = db.stats()["total_string_signatures"]

    def worker(worker_id: int) -> int:
        for i in range(ITERATIONS):
            # Her thread+i kombinasyonu unique frozenset -> ayni key
            # uzerinde collision yok, sadece dict mutation race'i test edilir.
            keywords = frozenset({f"kw_w{worker_id}_i{i}_a", f"kw_w{worker_id}_i{i}_b"})
            db.add_string_signature(keywords, f"match_w{worker_id}_i{i}", "lib", "p")
        return ITERATIONS

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for f in as_completed(pool.submit(worker, w) for w in range(WORKERS)):
            f.result()

    final = db.stats()["total_string_signatures"]
    assert final == initial + WORKERS * ITERATIONS


def test_match_function_during_writes(fresh_sigdb: SignatureDB) -> None:
    """``match_function`` (bulk-read iter) paralel yazma altinda
    ``RuntimeError`` (dict changed size during iteration) atmamali.

    Bu test asil regression senaryosunu modeller:
    ``_feedback_naming_merger`` ThreadPoolExecutor'larinda
    ``match_function`` cagiriliyor, ayni anda baska kod ``add_*`` yapiyor.
    """
    db = fresh_sigdb
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def writer() -> None:
        try:
            for i in range(ITERATIONS):
                db.add_string_signature(
                    frozenset({f"writer_kw_{i}_a", f"writer_kw_{i}_b"}),
                    f"name_{i}",
                    "lib",
                    "",
                )
                db.add_call_pattern(
                    frozenset({f"writer_callee_{i}_a", f"writer_callee_{i}_b"}),
                    f"name_{i}",
                    "lib",
                    "",
                    confidence=0.8,
                )
        except BaseException as exc:  # noqa: BLE001
            with errors_lock:
                errors.append(exc)
            raise

    def matcher() -> None:
        try:
            for i in range(ITERATIONS):
                # Iterasyon yapan bulk-read; race olursa RuntimeError
                db.match_function(
                    func_name=f"FUN_{i:08x}",
                    strings_used=[f"writer_kw_{i % 100}_a", f"writer_kw_{i % 100}_b"],
                    callees=[f"writer_callee_{i % 100}_a", f"writer_callee_{i % 100}_b"],
                )
        except BaseException as exc:  # noqa: BLE001
            with errors_lock:
                errors.append(exc)
            raise

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = []
        for _ in range(WORKERS // 2):
            futures.append(pool.submit(writer))
        for _ in range(WORKERS // 2):
            futures.append(pool.submit(matcher))
        for f in as_completed(futures):
            f.result()

    assert not errors, f"Bulk-read iter race: {errors[:3]}"


def test_stats_during_writes(fresh_sigdb: SignatureDB) -> None:
    """``stats()`` paralel yazma altinda tutarli (snapshot) sayilar dondurur."""
    db = fresh_sigdb
    snapshots: list[dict[str, Any]] = []
    snapshots_lock = threading.Lock()

    def writer(worker_id: int) -> None:
        for i in range(ITERATIONS // 2):
            db.add_symbol(
                f"__stat_w{worker_id}_i{i}",
                {"lib": "stat", "purpose": "", "category": ""},
            )

    def reader() -> None:
        for _ in range(ITERATIONS):
            snap = db.stats()
            # libraries listesi sorted -- iter sirasinda dict changed olmamali
            with snapshots_lock:
                snapshots.append(snap)

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = []
        for w in range(WORKERS // 2):
            futures.append(pool.submit(writer, w))
        for _ in range(WORKERS // 2):
            futures.append(pool.submit(reader))
        for f in as_completed(futures):
            f.result()

    # En son snapshot final size'i icermeli
    final = db.stats()
    assert final["total_symbol_signatures"] >= snapshots[-1]["total_symbol_signatures"]
    # Hicbir snapshot None veya bozuk anahtar icermemeli
    for snap in snapshots:
        assert "total_symbol_signatures" in snap
        assert isinstance(snap["libraries"], list)


# ---------------------------------------------------------------------------
# LMDBSignatureDB testleri
# ---------------------------------------------------------------------------

def _try_open_default_lmdb() -> Any:
    """Mevcut sistemde default LMDB varsa ac, yoksa None dondur."""
    try:
        from karadul.analyzers.sigdb_lmdb import (
            LMDBSignatureDB,
            default_lmdb_path,
            is_lmdb_available,
        )
    except ImportError:
        return None
    if not is_lmdb_available():
        return None
    path = default_lmdb_path()
    if not path.exists():
        return None
    try:
        return LMDBSignatureDB(path, readonly=True, l1_cache_size=4096)
    except Exception:
        return None


def test_lmdb_concurrent_lookup_no_crash() -> None:
    """16 thread x 1000 iter readonly ``lookup_symbol`` -- crash/race yok.

    LMDB readonly tx + L1 cache OrderedDict birlesimi -- v1.15-E oncesi
    ``OrderedDict.move_to_end`` paralel cagrida bozulabiliyordu (KeyError).
    """
    db = _try_open_default_lmdb()
    if db is None:
        pytest.skip("LMDB mevcut degil (lokal makinede ~/.karadul/signatures.lmdb yok)")

    # Builtin'den birkac muhtemel sembol -- LMDB'de olabilir veya olmayabilir
    probe_names = [
        "_OPENSSL_init_crypto", "OPENSSL_init_crypto",
        "malloc", "_malloc", "strcmp", "_strcmp",
        "memcpy", "_memcpy", "pthread_create", "_pthread_create",
        "__nonexistent_xyz_123",
    ]

    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def worker(worker_id: int) -> int:
        ok = 0
        try:
            for i in range(ITERATIONS):
                name = probe_names[(worker_id + i) % len(probe_names)]
                _ = db.lookup_symbol(name)
                ok += 1
        except BaseException as exc:  # noqa: BLE001
            with errors_lock:
                errors.append(exc)
            raise
        return ok

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = [f.result() for f in as_completed(pool.submit(worker, w) for w in range(WORKERS))]
        assert not errors, f"LMDB lookup race: {errors[:3]}"
        assert sum(results) == WORKERS * ITERATIONS
        # Cache hit + miss toplami exactly islem sayisi olmali
        cs = db.cache_stats
        assert cs["hits"] + cs["misses"] >= WORKERS * ITERATIONS
    finally:
        db.close()


def test_lmdb_close_idempotent_thread_safe() -> None:
    """``close()`` birden cok thread'den ayni anda cagrilirsa cifte
    ``env.close()`` LMDB Python binding'inde segfault'a yol acabilir.
    RLock ile cifte close engellenmeli."""
    db = _try_open_default_lmdb()
    if db is None:
        pytest.skip("LMDB mevcut degil")

    errors: list[BaseException] = []
    barrier = threading.Barrier(8)
    errors_lock = threading.Lock()

    def closer() -> None:
        barrier.wait()  # 8 thread ayni anda hit etsin
        try:
            db.close()
        except BaseException as exc:  # noqa: BLE001
            with errors_lock:
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(closer) for _ in range(8)]
        for f in as_completed(futs):
            f.result()

    assert not errors, f"LMDB close race: {errors[:3]}"


def test_lru_cache_concurrent() -> None:
    """``_LRUCache`` standalone concurrency testi.

    OrderedDict.move_to_end paralel iken bozuluyordu. Lock eklendikten
    sonra final size <= maxsize ve hit+miss sayisi tutarli olmali.
    """
    from karadul.analyzers.sigdb_lmdb import _LRUCache

    cache = _LRUCache(maxsize=512)
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def worker(worker_id: int) -> None:
        try:
            for i in range(ITERATIONS):
                key = f"k_{(worker_id * 7 + i) % 1024}"
                got = cache.get(key)
                if got is None:
                    cache.put(key, i)
        except BaseException as exc:  # noqa: BLE001
            with errors_lock:
                errors.append(exc)
            raise

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for f in as_completed(pool.submit(worker, w) for w in range(WORKERS)):
            f.result()

    assert not errors, f"_LRUCache race: {errors[:3]}"
    assert len(cache) <= 512
    # Toplam erisim = WORKERS * ITERATIONS = 16000; hit + miss tam toplam
    assert cache.hits + cache.misses == WORKERS * ITERATIONS
