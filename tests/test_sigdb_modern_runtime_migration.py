"""sig_db Faz 7 — modern_runtime (Rust + Go) migration parity testleri.

Amac: karadul/analyzers/sigdb_builtin/modern_runtime.py modulune eklenen
yeni dict'lerin (``rust_runtime_signatures`` + ``go_runtime_signatures``)
signature_db.py icine dogru override pattern'i ile baglanip baglanmadigini
dogrular. Ek olarak:

  - Schema parite (her entry ``lib`` / ``purpose`` / ``category`` tutar)
  - Cross-platform kategori etiketleri (``rust_*`` / ``go_*``)
  - Mangled symbol prefix'lerinin mevcudiyeti (``_ZN4core9panicking``)
  - Tipik modern crate/paket sembollerinin bulunabilirligi
    (tokio::runtime::Runtime::new, reqwest::Client::new, net/http.Get,
    crypto/tls.Dial, runtime.mapaccess1_fast64)
  - Legacy dict'lerin BOZULMADIGI (`_RUST_STDLIB_SIGNATURES`,
    `_GO_RUNTIME_SIGNATURES` hala erisilebilir ve doldurulmus).

pe_runtime / compression / network migration testlerinin pattern'ini takip
eder.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# 1. Yeni modul dogru yukleniyor mu?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_modern_runtime_importable() -> None:
    """sigdb_builtin.modern_runtime import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import modern_runtime

    assert hasattr(modern_runtime, "SIGNATURES")
    assert isinstance(modern_runtime.SIGNATURES, dict)
    assert len(modern_runtime.SIGNATURES) == 2


def test_sigdb_builtin_modern_runtime_has_expected_keys() -> None:
    """SIGNATURES 2 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import modern_runtime

    expected = {"rust_runtime_signatures", "go_runtime_signatures"}
    assert set(modern_runtime.SIGNATURES.keys()) == expected


def test_sigdb_builtin_modern_runtime_nonempty() -> None:
    """Her iki dict de dolu (minimum 80/100 entry)."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    # Gorev talimatlari: Rust ~80-120, Go ~100-150 (alt sinir)
    assert len(_RUST_RUNTIME_SIGNATURES_DATA) >= 80, (
        f"Rust runtime entry az: {len(_RUST_RUNTIME_SIGNATURES_DATA)}"
    )
    assert len(_GO_RUNTIME_SIGNATURES_DATA) >= 100, (
        f"Go runtime entry az: {len(_GO_RUNTIME_SIGNATURES_DATA)}"
    )


# ---------------------------------------------------------------------------
# 2. Schema parity — her entry dogru field'lari tasiyor mu?
# ---------------------------------------------------------------------------

def test_rust_entries_schema() -> None:
    """Her Rust entry {'lib', 'purpose', 'category'} anahtarlarini tasir."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    for key, meta in _RUST_RUNTIME_SIGNATURES_DATA.items():
        assert isinstance(meta, dict), f"{key}: meta dict degil"
        assert set(meta.keys()) == {"lib", "purpose", "category"}, (
            f"{key}: beklenmeyen keys {set(meta.keys())}"
        )
        assert isinstance(meta["lib"], str) and meta["lib"]
        assert isinstance(meta["purpose"], str) and meta["purpose"]
        assert isinstance(meta["category"], str) and meta["category"]


def test_go_entries_schema() -> None:
    """Her Go entry {'lib', 'purpose', 'category'} anahtarlarini tasir."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for key, meta in _GO_RUNTIME_SIGNATURES_DATA.items():
        assert isinstance(meta, dict), f"{key}: meta dict degil"
        assert set(meta.keys()) == {"lib", "purpose", "category"}, (
            f"{key}: beklenmeyen keys {set(meta.keys())}"
        )
        assert isinstance(meta["lib"], str) and meta["lib"]
        assert isinstance(meta["purpose"], str) and meta["purpose"]
        assert isinstance(meta["category"], str) and meta["category"]


# ---------------------------------------------------------------------------
# 3. Kategori etiketleri cross-platform (rust_* / go_*)
# ---------------------------------------------------------------------------

def test_rust_categories_use_rust_prefix() -> None:
    """Tum Rust entry kategorileri `rust_` ile baslar (platform-bagimsiz)."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    for key, meta in _RUST_RUNTIME_SIGNATURES_DATA.items():
        cat = meta["category"]
        assert cat.startswith("rust_"), (
            f"{key}: kategori `rust_` ile baslamiyor: {cat!r}"
        )


def test_go_categories_use_go_prefix() -> None:
    """Tum Go entry kategorileri `go_` ile baslar (platform-bagimsiz)."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for key, meta in _GO_RUNTIME_SIGNATURES_DATA.items():
        cat = meta["category"]
        assert cat.startswith("go_"), (
            f"{key}: kategori `go_` ile baslamiyor: {cat!r}"
        )


def test_rust_categories_cover_expected_subcategories() -> None:
    """Beklenen alt kategoriler mevcut (rust_runtime, rust_async, rust_crypto, rust_network)."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    cats = {meta["category"] for meta in _RUST_RUNTIME_SIGNATURES_DATA.values()}
    assert "rust_runtime" in cats
    assert "rust_async" in cats
    assert "rust_crypto" in cats
    assert "rust_network" in cats


def test_go_categories_cover_expected_subcategories() -> None:
    """Beklenen alt kategoriler mevcut (go_runtime, go_network, go_crypto, go_io)."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    cats = {meta["category"] for meta in _GO_RUNTIME_SIGNATURES_DATA.values()}
    assert "go_runtime" in cats
    assert "go_network" in cats
    assert "go_crypto" in cats
    assert "go_io" in cats


# ---------------------------------------------------------------------------
# 4. Dispatcher override aktif mi?
# ---------------------------------------------------------------------------

def test_override_modern_runtime_identity() -> None:
    """signature_db._MODERN_XXX_SIGNATURES ile builtin.modern_runtime ayni obje."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        SIGNATURES as builtin,
    )

    assert sdb._BUILTIN_MODERN_RUNTIME_SIGNATURES is not None
    assert sdb._MODERN_RUST_RUNTIME_SIGNATURES is builtin["rust_runtime_signatures"]
    assert sdb._MODERN_GO_RUNTIME_SIGNATURES is builtin["go_runtime_signatures"]


def test_modern_runtime_nonempty_after_override() -> None:
    """Override sonrasi yeni dict'ler dolu (fallback calismadi)."""
    from karadul.analyzers import signature_db as sdb

    assert len(sdb._MODERN_RUST_RUNTIME_SIGNATURES) >= 80
    assert len(sdb._MODERN_GO_RUNTIME_SIGNATURES) >= 100


# ---------------------------------------------------------------------------
# 5. Legacy Rust/Go dict'leri BOZULMADI
# ---------------------------------------------------------------------------

def test_legacy_rust_stdlib_intact() -> None:
    """Mevcut _RUST_STDLIB_SIGNATURES dokunulmadi."""
    from karadul.analyzers import signature_db as sdb

    assert hasattr(sdb, "_RUST_STDLIB_SIGNATURES")
    assert len(sdb._RUST_STDLIB_SIGNATURES) > 0
    # Bilindik bir entry kaybolmamali
    assert "__ZN3std2io5stdio6_print" in sdb._RUST_STDLIB_SIGNATURES


def test_legacy_go_runtime_intact() -> None:
    """Mevcut _GO_RUNTIME_SIGNATURES dokunulmadi."""
    from karadul.analyzers import signature_db as sdb

    assert hasattr(sdb, "_GO_RUNTIME_SIGNATURES")
    assert len(sdb._GO_RUNTIME_SIGNATURES) > 0
    # Bilindik bir entry kaybolmamali
    assert "runtime.newproc" in sdb._GO_RUNTIME_SIGNATURES


def test_legacy_rust_ext_intact() -> None:
    """Mevcut _RUST_EXT_SIGNATURES dokunulmadi (tokio/reqwest mangled prefix)."""
    from karadul.analyzers import signature_db as sdb

    assert "__ZN5tokio7runtime" in sdb._RUST_EXT_SIGNATURES
    assert "__ZN7reqwest" in sdb._RUST_EXT_SIGNATURES


# ---------------------------------------------------------------------------
# 6. Mangled prefix ve modern crate sembolleri mevcut
# ---------------------------------------------------------------------------

def test_rust_core_panicking_mangled_present() -> None:
    """`_ZN4core9panicking` prefix'i yeni modulde mevcut (Rust demangle detect)."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    # Itanium mangling: core::panicking::panic
    assert "_ZN4core9panicking5panic" in _RUST_RUNTIME_SIGNATURES_DATA
    assert "_ZN4core9panicking9panic_fmt" in _RUST_RUNTIME_SIGNATURES_DATA
    entry = _RUST_RUNTIME_SIGNATURES_DATA["_ZN4core9panicking5panic"]
    assert entry["category"].startswith("rust_")


def test_rust_global_allocator_present() -> None:
    """Rust global allocator (__rust_alloc ailesi) mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("__rust_alloc", "__rust_dealloc", "__rust_realloc",
                "__rust_alloc_zeroed"):
        assert sym in _RUST_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"


def test_rust_unwind_symbols_present() -> None:
    """Itanium ABI unwind sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("_Unwind_Resume", "_Unwind_RaiseException",
                "rust_eh_personality", "rust_begin_unwind"):
        assert sym in _RUST_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"


def test_rust_tokio_async_symbols_present() -> None:
    """Tokio async runtime kritik sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("tokio::runtime::Runtime::new",
                "tokio::runtime::Runtime::block_on",
                "tokio::task::spawn", "tokio::time::sleep"):
        assert sym in _RUST_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"
        assert _RUST_RUNTIME_SIGNATURES_DATA[sym]["category"] == "rust_async"


def test_rust_http_crates_present() -> None:
    """reqwest + hyper HTTP crate sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("reqwest::Client::new", "reqwest::get",
                "hyper::Server::bind", "hyper::Client::new"):
        assert sym in _RUST_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"
        assert _RUST_RUNTIME_SIGNATURES_DATA[sym]["category"] == "rust_network"


def test_rust_crypto_crates_present() -> None:
    """aes + aes-gcm + chacha20poly1305 crypto crate sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("aes::Aes128::new", "aes::Aes256::new",
                "aes_gcm::Aes128Gcm::encrypt",
                "chacha20::ChaCha20::new",
                "chacha20poly1305::ChaCha20Poly1305::encrypt"):
        assert sym in _RUST_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"
        assert _RUST_RUNTIME_SIGNATURES_DATA[sym]["category"] == "rust_crypto"


def test_rust_serde_and_clap_present() -> None:
    """serde + clap + structopt sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _RUST_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("serde::ser::Serialize::serialize",
                "serde::de::Deserialize::deserialize",
                "clap::Parser::parse",
                "structopt::StructOpt::from_args"):
        assert sym in _RUST_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"


def test_go_scheduler_core_present() -> None:
    """Go scheduler/goroutine core sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("runtime.main", "runtime.goexit", "runtime.morestack",
                "runtime.gopark", "runtime.newproc", "runtime.gogo",
                "runtime.schedule"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"
        assert _GO_RUNTIME_SIGNATURES_DATA[sym]["category"] == "go_runtime"


def test_go_memory_and_map_fastpath_present() -> None:
    """Go memory allocator + map fast-path variant'lari mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("runtime.mallocgc", "runtime.makeslice", "runtime.makemap",
                "runtime.mapaccess1_fast64", "runtime.mapassign_fast64",
                "runtime.mapdelete"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"


def test_go_channel_ops_present() -> None:
    """Go channel send/recv/close operasyonlari mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("runtime.chansend1", "runtime.chanrecv1",
                "runtime.makechan", "runtime.selectgo"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"


def test_go_gc_present() -> None:
    """Go GC bg worker + gcStart mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("runtime.gcStart", "runtime.gcBgMarkWorker"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"


def test_go_panic_recover_present() -> None:
    """Go panic/recover/throw mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("runtime.panic", "runtime.gopanic", "runtime.gorecover",
                "runtime.throw"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"


def test_go_type_conversion_present() -> None:
    """Go type/interface conversion helper'lari mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("runtime.convT2E", "runtime.assertI2T", "runtime.typehash"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"


def test_go_network_http_present() -> None:
    """Go net + net/http sembolleri mevcut (malware C2 tipik)."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("net.Dial", "net.Listen",
                "net/http.Get", "net/http.NewRequest",
                "net/http.(*Client).Do",
                "net/http.ListenAndServe"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"
        assert _GO_RUNTIME_SIGNATURES_DATA[sym]["category"] == "go_network"


def test_go_crypto_tls_present() -> None:
    """Go crypto/aes + crypto/cipher + crypto/tls mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("crypto/aes.NewCipher", "crypto/cipher.NewGCM",
                "crypto/tls.Dial", "crypto/tls.Listen",
                "crypto/tls.(*Conn).Read"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"
        assert _GO_RUNTIME_SIGNATURES_DATA[sym]["category"] == "go_crypto"


def test_go_encoding_json_base64_present() -> None:
    """encoding/json + encoding/base64 mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("encoding/json.Marshal", "encoding/json.Unmarshal",
                "encoding/base64.StdEncoding.EncodeToString",
                "encoding/base64.StdEncoding.DecodeString"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"
        assert _GO_RUNTIME_SIGNATURES_DATA[sym]["category"] == "go_io"


def test_go_os_and_fmt_present() -> None:
    """os + fmt paket sembolleri mevcut."""
    from karadul.analyzers.sigdb_builtin.modern_runtime import (
        _GO_RUNTIME_SIGNATURES_DATA,
    )

    for sym in ("os.Open", "os.Create", "os.Exit", "os.Getenv", "os.Args",
                "fmt.Printf", "fmt.Sprintf", "fmt.Println"):
        assert sym in _GO_RUNTIME_SIGNATURES_DATA, f"missing: {sym}"


# ---------------------------------------------------------------------------
# 7. SignatureDB instance yeni sembolleri cozebiliyor mu?
# ---------------------------------------------------------------------------

def test_signature_db_resolves_modern_rust_symbol() -> None:
    """SignatureDB() instance tokio async sembollerini bulabiliyor."""
    from karadul.analyzers.signature_db import SignatureDB

    db = SignatureDB()
    assert "tokio::runtime::Runtime::new" in db._symbol_db
    entry = db._symbol_db["tokio::runtime::Runtime::new"]
    assert entry["lib"] == "tokio"
    assert entry["category"] == "rust_async"


def test_signature_db_resolves_modern_go_symbol() -> None:
    """SignatureDB() instance Go net/http sembollerini bulabiliyor."""
    from karadul.analyzers.signature_db import SignatureDB

    db = SignatureDB()
    assert "net/http.Get" in db._symbol_db
    entry = db._symbol_db["net/http.Get"]
    assert entry["lib"] == "net/http"
    assert entry["category"] == "go_network"


def test_signature_db_resolves_go_fastpath_symbol() -> None:
    """SignatureDB() instance Go map fast-path sembollerini bulabiliyor."""
    from karadul.analyzers.signature_db import SignatureDB

    db = SignatureDB()
    assert "runtime.mapaccess1_fast64" in db._symbol_db
    assert "runtime.mapassign_fast64" in db._symbol_db


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
