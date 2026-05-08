"""Runtimes category signatures (sig_db Faz A5).

Modern runtime category signatures - sig_db Faz A5 migrasyonu (ADR 0007).

Bu modul "yonetilen" / "runtime'a sahip" dilleri toplar:
  Rust + Go + Python C API + Java JNI + .NET CLR/Mono/IL2CPP.

Kaynak: karadul/analyzers/signature_db.py
  - _RUST_STDLIB_SIGNATURES   (47 entry,  satir 4428-4525)
  - _RUST_EXT_SIGNATURES      (75 entry,  satir 5331-5438)
  - _GO_RUNTIME_SIGNATURES    (53 entry,  satir 4534-4617)
  - _GO_EXT_SIGNATURES        (209 entry, satir 5446-5713)
  - _PYTHON_CAPI_SIGNATURES   (76 entry,  satir 6126-6220)
  - _JAVA_JNI_SIGNATURES      (50 entry,  satir 6228-6280)
  - _DOTNET_CLR_SIGNATURES    (58 entry,  satir 6288-6354)

Toplam: 568 signature.

ADR 0007 v1.13 Dalga 2 Faz A5 - Grup "Runtimes". Parity testleri
``tests/test_sigdb_runtimes_migration.py`` icinde dogrulanir.

Bu modul signature_db.py'a dokunmadan calisir; signature_db.py icindeki
orijinal _RUST_* / _GO_* / _PYTHON_* / _JAVA_* / _DOTNET_* dict'leri
SILINMEMISTIR (rollback / shadow legacy bandi korunur). v1.13 sonrasi
Faz A-DELETE'te legacy gövdeler dismantle edilir.

Not: ``modern_runtime.py`` modulu Faz B (PE/modern_runtime grubu) altinda
farkli sembolleri (.NET PE artefaktlari, Mono ICalls, Swift mangle prefix'leri)
tasimaktadir; ``runtimes`` ile ortusme yoktur.

Anahtar isimleri orijinal dict adlariyla uyumludur:
  ``rust_stdlib_signatures``    <-> ``_RUST_STDLIB_SIGNATURES``
  ``rust_ext_signatures``       <-> ``_RUST_EXT_SIGNATURES``
  ``go_runtime_signatures``     <-> ``_GO_RUNTIME_SIGNATURES``
  ``go_ext_signatures``         <-> ``_GO_EXT_SIGNATURES``
  ``python_capi_signatures``    <-> ``_PYTHON_CAPI_SIGNATURES``
  ``java_jni_signatures``       <-> ``_JAVA_JNI_SIGNATURES``
  ``dotnet_clr_signatures``     <-> ``_DOTNET_CLR_SIGNATURES``
"""

from __future__ import annotations

from typing import Any



# -------------------------------------------------------------------------
# Rust std/core/alloc (47 entry) - v0 mangling prefixes + legacy std::io / panic /
# core::fmt / Result / Option / collections / sync / thread / time / process /
# env. Kaynak: signature_db.py satir 4428-4525.
# -------------------------------------------------------------------------
_RUST_STDLIB_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # -- v0 mangling prefixes --
    "_RNvNtCs": {"lib": "rust-std", "purpose": "Rust v0 mangled symbol (core/std crate)", "category": "rust"},

    # -- Legacy mangling: std::io --
    "__ZN3std2io5stdio6_print": {"lib": "rust-std", "purpose": "std::io::stdio::_print (formatted output)", "category": "rust_io"},
    "__ZN3std2io5stdio7_eprint": {"lib": "rust-std", "purpose": "std::io::stdio::_eprint (formatted stderr)", "category": "rust_io"},
    "__ZN3std2io4Read": {"lib": "rust-std", "purpose": "std::io::Read trait methods", "category": "rust_io"},
    "__ZN3std2io5Write": {"lib": "rust-std", "purpose": "std::io::Write trait methods", "category": "rust_io"},
    "__ZN3std2io5Error": {"lib": "rust-std", "purpose": "std::io::Error methods", "category": "rust_io"},
    "__ZN3std2io6BufRead": {"lib": "rust-std", "purpose": "std::io::BufRead trait methods", "category": "rust_io"},

    # -- Legacy mangling: std::panic --
    "__ZN3std5panic15begin_panic": {"lib": "rust-std", "purpose": "std::panic::begin_panic (panic entry)", "category": "rust_panic"},
    "__ZN3std9panicking": {"lib": "rust-std", "purpose": "std::panicking internal machinery", "category": "rust_panic"},
    "__ZN4core9panicking": {"lib": "rust-core", "purpose": "core::panicking (panic in no-std)", "category": "rust_panic"},

    # -- Legacy mangling: core::fmt --
    "__ZN4core3fmt": {"lib": "rust-core", "purpose": "core::fmt formatting infrastructure", "category": "rust_fmt"},
    "__ZN4core3fmt5Write": {"lib": "rust-core", "purpose": "core::fmt::Write trait methods", "category": "rust_fmt"},
    "__ZN4core3fmt9Formatter": {"lib": "rust-core", "purpose": "core::fmt::Formatter methods", "category": "rust_fmt"},
    "__ZN4core3fmt10ArgumentV1": {"lib": "rust-core", "purpose": "core::fmt::ArgumentV1 (format args)", "category": "rust_fmt"},

    # -- Legacy mangling: core::result --
    "__ZN4core6result": {"lib": "rust-core", "purpose": "core::result::Result methods", "category": "rust_core"},

    # -- Legacy mangling: core::option --
    "__ZN4core6option": {"lib": "rust-core", "purpose": "core::option::Option methods", "category": "rust_core"},

    # -- Legacy mangling: core::slice --
    "__ZN4core5slice": {"lib": "rust-core", "purpose": "core::slice methods", "category": "rust_core"},

    # -- Legacy mangling: core::str --
    "__ZN4core3str": {"lib": "rust-core", "purpose": "core::str string slice methods", "category": "rust_core"},

    # -- Legacy mangling: core::ptr --
    "__ZN4core3ptr": {"lib": "rust-core", "purpose": "core::ptr raw pointer operations", "category": "rust_core"},

    # -- Legacy mangling: core::ops --
    "__ZN4core3ops": {"lib": "rust-core", "purpose": "core::ops operator trait impls", "category": "rust_core"},

    # -- Legacy mangling: core::iter --
    "__ZN4core4iter": {"lib": "rust-core", "purpose": "core::iter iterator infrastructure", "category": "rust_core"},

    # -- Legacy mangling: alloc::vec --
    "__ZN5alloc3vec": {"lib": "rust-alloc", "purpose": "alloc::vec::Vec methods", "category": "rust_collections"},

    # -- Legacy mangling: alloc::string --
    "__ZN5alloc6string": {"lib": "rust-alloc", "purpose": "alloc::string::String methods", "category": "rust_collections"},

    # -- Legacy mangling: alloc::boxed --
    "__ZN5alloc5boxed": {"lib": "rust-alloc", "purpose": "alloc::boxed::Box methods", "category": "rust_collections"},

    # -- Legacy mangling: alloc::rc --
    "__ZN5alloc2rc": {"lib": "rust-alloc", "purpose": "alloc::rc::Rc reference counting", "category": "rust_collections"},

    # -- Legacy mangling: alloc::sync --
    "__ZN5alloc4sync": {"lib": "rust-alloc", "purpose": "alloc::sync::Arc atomic reference counting", "category": "rust_collections"},

    # -- Legacy mangling: std::fs --
    "__ZN3std2fs": {"lib": "rust-std", "purpose": "std::fs file system operations", "category": "rust_io"},

    # -- Legacy mangling: std::net --
    "__ZN3std3net": {"lib": "rust-std", "purpose": "std::net networking (TCP/UDP)", "category": "rust_net"},

    # -- Legacy mangling: std::sync --
    "__ZN3std4sync5mutex": {"lib": "rust-std", "purpose": "std::sync::Mutex methods", "category": "rust_sync"},
    "__ZN3std4sync6rwlock": {"lib": "rust-std", "purpose": "std::sync::RwLock methods", "category": "rust_sync"},
    "__ZN3std4sync4mpsc": {"lib": "rust-std", "purpose": "std::sync::mpsc channel methods", "category": "rust_sync"},
    "__ZN3std4sync7condvar": {"lib": "rust-std", "purpose": "std::sync::Condvar methods", "category": "rust_sync"},
    "__ZN3std4sync6atomic": {"lib": "rust-std", "purpose": "std::sync::atomic operations", "category": "rust_sync"},
    "__ZN3std4sync4Once": {"lib": "rust-std", "purpose": "std::sync::Once one-time init", "category": "rust_sync"},

    # -- Legacy mangling: std::thread --
    "__ZN3std6thread": {"lib": "rust-std", "purpose": "std::thread thread management", "category": "rust_thread"},

    # -- Legacy mangling: std::time --
    "__ZN3std4time": {"lib": "rust-std", "purpose": "std::time (Duration, Instant, SystemTime)", "category": "rust_time"},

    # -- Legacy mangling: std::process --
    "__ZN3std7process": {"lib": "rust-std", "purpose": "std::process (Command, Child, exit)", "category": "rust_process"},

    # -- Legacy mangling: std::env --
    "__ZN3std3env": {"lib": "rust-std", "purpose": "std::env environment variables", "category": "rust_env"},

    # -- Legacy mangling: std::collections --
    "__ZN3std11collections4hash3map": {"lib": "rust-std", "purpose": "std::collections::HashMap methods", "category": "rust_collections"},
    "__ZN3std11collections4hash3set": {"lib": "rust-std", "purpose": "std::collections::HashSet methods", "category": "rust_collections"},
    "__ZN3std11collections6btree": {"lib": "rust-std", "purpose": "std::collections::BTreeMap/Set methods", "category": "rust_collections"},
    "__ZN5alloc11collections7vec_deque": {"lib": "rust-alloc", "purpose": "alloc::collections::VecDeque methods", "category": "rust_collections"},
    "__ZN5alloc11collections10linked_list": {"lib": "rust-alloc", "purpose": "alloc::collections::LinkedList methods", "category": "rust_collections"},
    "__ZN5alloc11collections12binary_heap": {"lib": "rust-alloc", "purpose": "alloc::collections::BinaryHeap methods", "category": "rust_collections"},

    # -- Rust runtime support --
    "__ZN3std2rt": {"lib": "rust-std", "purpose": "std::rt runtime initialization", "category": "rust_runtime"},
    "__ZN3std10sys_common": {"lib": "rust-std", "purpose": "std::sys_common platform abstraction", "category": "rust_runtime"},
    "__ZN3std3sys": {"lib": "rust-std", "purpose": "std::sys platform-specific code", "category": "rust_runtime"},
}

# -------------------------------------------------------------------------
# Rust ekosistem (75 entry) - Tokio, async-std, serde + serde_json/cbor/bincode/
# toml, hyper/reqwest/actix/warp/axum, rustls/ring/sha2/aes/native-tls,
# diesel/sqlx/rusqlite, anyhow/thiserror, clap/structopt, crossbeam/rayon/
# parking_lot, regex, rand, chrono, Rust unwinding/panic & global allocator
# entry symbols. Kaynak: signature_db.py satir 5331-5438.
# -------------------------------------------------------------------------
_RUST_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # -- Tokio async runtime --
    "__ZN5tokio7runtime": {"lib": "tokio", "purpose": "tokio::runtime (async runtime)", "category": "rust_async"},
    "__ZN5tokio2io": {"lib": "tokio", "purpose": "tokio::io async I/O", "category": "rust_async"},
    "__ZN5tokio3net": {"lib": "tokio", "purpose": "tokio::net async networking", "category": "rust_async"},
    "__ZN5tokio4sync": {"lib": "tokio", "purpose": "tokio::sync async synchronization", "category": "rust_async"},
    "__ZN5tokio4task": {"lib": "tokio", "purpose": "tokio::task task spawning", "category": "rust_async"},
    "__ZN5tokio4time": {"lib": "tokio", "purpose": "tokio::time timers and delays", "category": "rust_async"},
    "__ZN5tokio6signal": {"lib": "tokio", "purpose": "tokio::signal signal handling", "category": "rust_async"},
    "__ZN5tokio7process": {"lib": "tokio", "purpose": "tokio::process async child process", "category": "rust_async"},
    "__ZN5tokio2fs": {"lib": "tokio", "purpose": "tokio::fs async filesystem", "category": "rust_async"},

    # -- async-std --
    "__ZN9async_std": {"lib": "async-std", "purpose": "async-std runtime", "category": "rust_async"},

    # -- serde --
    "__ZN5serde2de": {"lib": "serde", "purpose": "serde::de deserialization", "category": "rust_serde"},
    "__ZN5serde3ser": {"lib": "serde", "purpose": "serde::ser serialization", "category": "rust_serde"},
    "__ZN10serde_json": {"lib": "serde_json", "purpose": "serde_json JSON serde", "category": "rust_serde"},
    "__ZN11serde_cbor": {"lib": "serde_cbor", "purpose": "serde CBOR format", "category": "rust_serde"},
    "__ZN8bincode": {"lib": "bincode", "purpose": "bincode binary serialization", "category": "rust_serde"},
    "__ZN4toml": {"lib": "toml", "purpose": "TOML format serde", "category": "rust_serde"},

    # -- hyper / reqwest HTTP --
    "__ZN5hyper": {"lib": "hyper", "purpose": "hyper HTTP client/server", "category": "rust_http"},
    "__ZN7reqwest": {"lib": "reqwest", "purpose": "reqwest HTTP client", "category": "rust_http"},
    "__ZN4actix": {"lib": "actix", "purpose": "actix web framework", "category": "rust_http"},
    "__ZN4warp": {"lib": "warp", "purpose": "warp web framework", "category": "rust_http"},
    "__ZN4axum": {"lib": "axum", "purpose": "axum web framework", "category": "rust_http"},

    # -- core / alloc extended --
    "__ZN4core4hash": {"lib": "rust-core", "purpose": "core::hash hashing infrastructure", "category": "rust_core"},
    "__ZN4core3num": {"lib": "rust-core", "purpose": "core::num numeric parsing/conversion", "category": "rust_core"},
    "__ZN4core4char": {"lib": "rust-core", "purpose": "core::char Unicode character handling", "category": "rust_core"},
    "__ZN4core6marker": {"lib": "rust-core", "purpose": "core::marker trait implementations (Send/Sync)", "category": "rust_core"},
    "__ZN4core7convert": {"lib": "rust-core", "purpose": "core::convert From/Into/TryFrom traits", "category": "rust_core"},
    "__ZN4core3cmp": {"lib": "rust-core", "purpose": "core::cmp comparison trait impls", "category": "rust_core"},
    "__ZN4core5clone": {"lib": "rust-core", "purpose": "core::clone::Clone implementations", "category": "rust_core"},
    "__ZN4core7default": {"lib": "rust-core", "purpose": "core::default::Default implementations", "category": "rust_core"},
    "__ZN4core4cell": {"lib": "rust-core", "purpose": "core::cell interior mutability (Cell/RefCell)", "category": "rust_core"},
    "__ZN4core3mem": {"lib": "rust-core", "purpose": "core::mem memory manipulation (swap, drop, etc)", "category": "rust_core"},
    "__ZN4core4sync6atomic": {"lib": "rust-core", "purpose": "core::sync::atomic operations", "category": "rust_sync"},
    "__ZN4core5alloc": {"lib": "rust-core", "purpose": "core::alloc allocator traits", "category": "rust_core"},
    "__ZN4core8intrinsics": {"lib": "rust-core", "purpose": "core::intrinsics compiler intrinsics", "category": "rust_core"},
    "__ZN4core5array": {"lib": "rust-core", "purpose": "core::array fixed-size array operations", "category": "rust_core"},
    "__ZN4core4hint": {"lib": "rust-core", "purpose": "core::hint performance hints (black_box etc)", "category": "rust_core"},
    "__ZN4core5error": {"lib": "rust-core", "purpose": "core::error Error trait", "category": "rust_core"},
    "__ZN5alloc7raw_vec": {"lib": "rust-alloc", "purpose": "alloc::raw_vec::RawVec raw vector", "category": "rust_collections"},
    "__ZN5alloc6alloc": {"lib": "rust-alloc", "purpose": "alloc::alloc global allocator", "category": "rust_collections"},
    "__ZN5alloc4borrow": {"lib": "rust-alloc", "purpose": "alloc::borrow Cow borrow type", "category": "rust_collections"},
    "__ZN5alloc3fmt": {"lib": "rust-alloc", "purpose": "alloc::fmt formatting support", "category": "rust_core"},

    # -- std extended --
    "__ZN3std7ffi": {"lib": "rust-std", "purpose": "std::ffi foreign function interface (CString etc)", "category": "rust_ffi"},
    "__ZN3std5path": {"lib": "rust-std", "purpose": "std::path Path/PathBuf operations", "category": "rust_io"},
    "__ZN3std8backtrace": {"lib": "rust-std", "purpose": "std::backtrace stack trace capture", "category": "rust_debug"},
    "__ZN3std5error": {"lib": "rust-std", "purpose": "std::error Error trait extensions", "category": "rust_core"},

    # -- log / tracing --
    "__ZN3log": {"lib": "log", "purpose": "log crate logging facade", "category": "rust_log"},
    "__ZN7tracing": {"lib": "tracing", "purpose": "tracing instrumentation framework", "category": "rust_log"},
    "__ZN14tracing_subscriber": {"lib": "tracing-subscriber", "purpose": "tracing subscriber layer", "category": "rust_log"},
    "__ZN6env_logger": {"lib": "env_logger", "purpose": "env_logger logging backend", "category": "rust_log"},

    # -- crypto / TLS crates --
    "__ZN7rustls": {"lib": "rustls", "purpose": "rustls TLS implementation", "category": "rust_crypto"},
    "__ZN5ring": {"lib": "ring", "purpose": "ring cryptography library", "category": "rust_crypto"},
    "__ZN3sha2": {"lib": "sha2", "purpose": "sha2 hash crate", "category": "rust_crypto"},
    "__ZN3aes": {"lib": "aes", "purpose": "aes cipher crate", "category": "rust_crypto"},
    "__ZN10native_tls": {"lib": "native-tls", "purpose": "native-tls platform TLS", "category": "rust_crypto"},

    # -- database crates --
    "__ZN6diesel": {"lib": "diesel", "purpose": "diesel ORM/query builder", "category": "rust_db"},
    "__ZN4sqlx": {"lib": "sqlx", "purpose": "sqlx async SQL toolkit", "category": "rust_db"},
    "__ZN8rusqlite": {"lib": "rusqlite", "purpose": "rusqlite SQLite bindings", "category": "rust_db"},

    # -- error handling --
    "__ZN6anyhow": {"lib": "anyhow", "purpose": "anyhow flexible error handling", "category": "rust_error"},
    "__ZN9thiserror": {"lib": "thiserror", "purpose": "thiserror derive macro for Error", "category": "rust_error"},

    # -- CLI / args --
    "__ZN4clap": {"lib": "clap", "purpose": "clap command-line argument parser", "category": "rust_cli"},
    "__ZN10structopt": {"lib": "structopt", "purpose": "structopt CLI derive macro", "category": "rust_cli"},

    # -- concurrency --
    "__ZN8crossbeam": {"lib": "crossbeam", "purpose": "crossbeam concurrent utilities", "category": "rust_sync"},
    "__ZN5rayon": {"lib": "rayon", "purpose": "rayon data parallelism library", "category": "rust_sync"},
    "__ZN6parking_lot": {"lib": "parking_lot", "purpose": "parking_lot efficient sync primitives", "category": "rust_sync"},

    # -- regex --
    "__ZN5regex": {"lib": "regex", "purpose": "regex regular expression engine", "category": "rust_regex"},

    # -- rand --
    "__ZN4rand": {"lib": "rand", "purpose": "rand random number generation", "category": "rust_rand"},

    # -- chrono / time --
    "__ZN6chrono": {"lib": "chrono", "purpose": "chrono date/time library", "category": "rust_time"},

    # -- Rust unwinding / panic symbols (demangled) --
    "rust_begin_unwind": {"lib": "rust-std", "purpose": "Rust panic unwinding entry", "category": "rust_panic"},
    "rust_panic": {"lib": "rust-std", "purpose": "Rust panic handler", "category": "rust_panic"},
    "rust_eh_personality": {"lib": "rust-std", "purpose": "Rust exception personality function (LSDA)", "category": "rust_panic"},
    "__rust_alloc": {"lib": "rust-alloc", "purpose": "Rust global allocator entry (alloc)", "category": "rust_runtime"},
    "__rust_dealloc": {"lib": "rust-alloc", "purpose": "Rust global allocator entry (dealloc)", "category": "rust_runtime"},
    "__rust_realloc": {"lib": "rust-alloc", "purpose": "Rust global allocator entry (realloc)", "category": "rust_runtime"},
    "__rust_alloc_zeroed": {"lib": "rust-alloc", "purpose": "Rust global allocator entry (alloc_zeroed)", "category": "rust_runtime"},
    "__rust_alloc_error_handler": {"lib": "rust-alloc", "purpose": "Rust allocation failure handler", "category": "rust_runtime"},
}

# -------------------------------------------------------------------------
# Go runtime (53 entry) - main/goexit/newproc, mallocgc, channel ops, slice/map
# ops, sync primitives, GC, type conversion, stack, panic/recover, fmt/os/net/
# sync packages. Kaynak: signature_db.py satir 4534-4617.
# -------------------------------------------------------------------------
_GO_RUNTIME_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Core runtime
    "runtime.main": {"lib": "go-runtime", "purpose": "Go program main entry (calls main.main)", "category": "go_runtime"},
    "runtime.goexit": {"lib": "go-runtime", "purpose": "goroutine exit point", "category": "go_runtime"},
    "runtime.newproc": {"lib": "go-runtime", "purpose": "create new goroutine (go statement)", "category": "go_runtime"},
    "runtime.newproc1": {"lib": "go-runtime", "purpose": "create new goroutine (internal)", "category": "go_runtime"},

    # Memory allocation
    "runtime.mallocgc": {"lib": "go-runtime", "purpose": "GC-aware memory allocation", "category": "go_memory"},
    "runtime.makeslice": {"lib": "go-runtime", "purpose": "allocate and initialize slice", "category": "go_memory"},
    "runtime.makemap": {"lib": "go-runtime", "purpose": "allocate and initialize map", "category": "go_memory"},
    "runtime.makechan": {"lib": "go-runtime", "purpose": "allocate and initialize channel", "category": "go_memory"},

    # Channel operations
    "runtime.chansend": {"lib": "go-runtime", "purpose": "send value on channel (ch <- v)", "category": "go_channel"},
    "runtime.chanrecv": {"lib": "go-runtime", "purpose": "receive value from channel (<-ch)", "category": "go_channel"},
    "runtime.closechan": {"lib": "go-runtime", "purpose": "close a channel", "category": "go_channel"},

    # Slice operations
    "runtime.growslice": {"lib": "go-runtime", "purpose": "grow slice backing array (append)", "category": "go_slice"},
    "runtime.slicecopy": {"lib": "go-runtime", "purpose": "copy elements between slices", "category": "go_slice"},
    "runtime.slicebytetostring": {"lib": "go-runtime", "purpose": "convert []byte to string", "category": "go_slice"},

    # Map operations
    "runtime.mapaccess1": {"lib": "go-runtime", "purpose": "map lookup returning value (m[k])", "category": "go_map"},
    "runtime.mapaccess2": {"lib": "go-runtime", "purpose": "map lookup returning value+ok (v,ok=m[k])", "category": "go_map"},
    "runtime.mapassign": {"lib": "go-runtime", "purpose": "map assignment (m[k]=v)", "category": "go_map"},
    "runtime.mapdelete": {"lib": "go-runtime", "purpose": "map deletion (delete(m,k))", "category": "go_map"},

    # Synchronization
    "runtime.lock": {"lib": "go-runtime", "purpose": "runtime internal lock acquire", "category": "go_sync"},
    "runtime.unlock": {"lib": "go-runtime", "purpose": "runtime internal lock release", "category": "go_sync"},
    "runtime.semacquire": {"lib": "go-runtime", "purpose": "semaphore acquire (used by sync pkg)", "category": "go_sync"},
    "runtime.semrelease": {"lib": "go-runtime", "purpose": "semaphore release", "category": "go_sync"},

    # Garbage collection
    "runtime.gcStart": {"lib": "go-runtime", "purpose": "start garbage collection cycle", "category": "go_gc"},
    "runtime.gcDrain": {"lib": "go-runtime", "purpose": "drain GC mark work queue", "category": "go_gc"},
    "runtime.gcMarkDone": {"lib": "go-runtime", "purpose": "signal GC marking phase complete", "category": "go_gc"},

    # Type conversion
    "runtime.convT": {"lib": "go-runtime", "purpose": "convert concrete type to interface", "category": "go_runtime"},
    "runtime.convTstring": {"lib": "go-runtime", "purpose": "convert string to interface", "category": "go_runtime"},
    "runtime.convTslice": {"lib": "go-runtime", "purpose": "convert slice to interface", "category": "go_runtime"},

    # Stack management
    "runtime.morestack": {"lib": "go-runtime", "purpose": "goroutine stack growth", "category": "go_runtime"},
    "runtime.morestack_noctxt": {"lib": "go-runtime", "purpose": "goroutine stack growth (no closure context)", "category": "go_runtime"},
    "runtime.rt0_go": {"lib": "go-runtime", "purpose": "Go bootstrap entry point (before runtime.main)", "category": "go_runtime"},

    # Error / panic
    "runtime.throw": {"lib": "go-runtime", "purpose": "runtime fatal error (unrecoverable)", "category": "go_panic"},
    "runtime.gopanic": {"lib": "go-runtime", "purpose": "Go panic() entry point", "category": "go_panic"},
    "runtime.gorecover": {"lib": "go-runtime", "purpose": "Go recover() entry point", "category": "go_panic"},

    # Print (used by runtime.throw)
    "runtime.printstring": {"lib": "go-runtime", "purpose": "runtime internal string print", "category": "go_runtime"},
    "runtime.printint": {"lib": "go-runtime", "purpose": "runtime internal int print", "category": "go_runtime"},
    "runtime.printnl": {"lib": "go-runtime", "purpose": "runtime internal newline print", "category": "go_runtime"},

    # fmt package
    "fmt.Fprintf": {"lib": "go-fmt", "purpose": "formatted I/O to io.Writer", "category": "go_fmt"},
    "fmt.Sprintf": {"lib": "go-fmt", "purpose": "formatted string return", "category": "go_fmt"},
    "fmt.Printf": {"lib": "go-fmt", "purpose": "formatted I/O to stdout", "category": "go_fmt"},
    "fmt.Println": {"lib": "go-fmt", "purpose": "print with newline to stdout", "category": "go_fmt"},

    # os package
    "os.Open": {"lib": "go-os", "purpose": "open file for reading", "category": "go_os"},
    "os.Create": {"lib": "go-os", "purpose": "create or truncate file", "category": "go_os"},
    "os.Exit": {"lib": "go-os", "purpose": "exit process with status code", "category": "go_os"},
    "os.Getenv": {"lib": "go-os", "purpose": "get environment variable", "category": "go_os"},

    # net package
    "net.Dial": {"lib": "go-net", "purpose": "connect to network address", "category": "go_net"},
    "net.Listen": {"lib": "go-net", "purpose": "listen on network address", "category": "go_net"},
    "net.(*TCPConn).Read": {"lib": "go-net", "purpose": "read data from TCP connection", "category": "go_net"},
    "net.(*TCPConn).Write": {"lib": "go-net", "purpose": "write data to TCP connection", "category": "go_net"},

    # sync package
    "sync.(*Mutex).Lock": {"lib": "go-sync", "purpose": "acquire mutex lock", "category": "go_sync"},
    "sync.(*Mutex).Unlock": {"lib": "go-sync", "purpose": "release mutex lock", "category": "go_sync"},
    "sync.(*WaitGroup).Add": {"lib": "go-sync", "purpose": "add delta to WaitGroup counter", "category": "go_sync"},
    "sync.(*WaitGroup).Wait": {"lib": "go-sync", "purpose": "block until WaitGroup counter is zero", "category": "go_sync"},
}

# -------------------------------------------------------------------------
# Go ekosistem genisletme (209 entry) - runtime extended (scheduler, GC, map
# fast variants, type assertion, defer), fmt/os/io/bufio/strings/strconv/bytes/
# net/net-http/encoding-json/base64/crypto/sync/context/errors/path-filepath/
# regexp/sort/log/time/exec/database-sql.
# Kaynak: signature_db.py satir 5446-5713.
# -------------------------------------------------------------------------
_GO_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- runtime extended ---
    "runtime.mstart": {"lib": "go-runtime", "purpose": "OS thread start routine for Go", "category": "go_runtime"},
    "runtime.mstart0": {"lib": "go-runtime", "purpose": "initial OS thread setup", "category": "go_runtime"},
    "runtime.schedinit": {"lib": "go-runtime", "purpose": "scheduler initialization", "category": "go_runtime"},
    "runtime.schedule": {"lib": "go-runtime", "purpose": "select next goroutine to run", "category": "go_runtime"},
    "runtime.findrunnable": {"lib": "go-runtime", "purpose": "find a runnable goroutine", "category": "go_runtime"},
    "runtime.park_m": {"lib": "go-runtime", "purpose": "park current goroutine", "category": "go_runtime"},
    "runtime.gopark": {"lib": "go-runtime", "purpose": "goroutine park (suspend)", "category": "go_runtime"},
    "runtime.goready": {"lib": "go-runtime", "purpose": "goroutine ready (resume)", "category": "go_runtime"},
    "runtime.Gosched": {"lib": "go-runtime", "purpose": "yield to scheduler (cooperative)", "category": "go_runtime"},
    "runtime.GOMAXPROCS": {"lib": "go-runtime", "purpose": "set max OS threads for goroutines", "category": "go_runtime"},
    "runtime.NumGoroutine": {"lib": "go-runtime", "purpose": "get number of goroutines", "category": "go_runtime"},
    "runtime.NumCPU": {"lib": "go-runtime", "purpose": "get number of CPUs", "category": "go_runtime"},
    "runtime.GC": {"lib": "go-runtime", "purpose": "trigger garbage collection", "category": "go_gc"},
    "runtime.SetFinalizer": {"lib": "go-runtime", "purpose": "set finalizer on object", "category": "go_gc"},
    "runtime.ReadMemStats": {"lib": "go-runtime", "purpose": "read memory allocator stats", "category": "go_gc"},
    "runtime.KeepAlive": {"lib": "go-runtime", "purpose": "prevent GC from collecting object", "category": "go_gc"},
    "runtime.gcBgMarkWorker": {"lib": "go-runtime", "purpose": "background GC mark worker", "category": "go_gc"},
    "runtime.gcSweep": {"lib": "go-runtime", "purpose": "GC sweep phase", "category": "go_gc"},
    "runtime.systemstack": {"lib": "go-runtime", "purpose": "switch to system stack", "category": "go_runtime"},
    "runtime.mcall": {"lib": "go-runtime", "purpose": "call function on m stack", "category": "go_runtime"},
    "runtime.gogo": {"lib": "go-runtime", "purpose": "switch to goroutine (context switch)", "category": "go_runtime"},
    "runtime.Caller": {"lib": "go-runtime", "purpose": "get calling goroutine stack info", "category": "go_runtime"},
    "runtime.Callers": {"lib": "go-runtime", "purpose": "get stack trace of goroutine", "category": "go_runtime"},
    "runtime.Stack": {"lib": "go-runtime", "purpose": "format stack trace", "category": "go_runtime"},

    # --- runtime: map internals ---
    "runtime.mapaccess1_fast32": {"lib": "go-runtime", "purpose": "fast map lookup (int32 key)", "category": "go_map"},
    "runtime.mapaccess1_fast64": {"lib": "go-runtime", "purpose": "fast map lookup (int64 key)", "category": "go_map"},
    "runtime.mapaccess1_faststr": {"lib": "go-runtime", "purpose": "fast map lookup (string key)", "category": "go_map"},
    "runtime.mapassign_fast32": {"lib": "go-runtime", "purpose": "fast map assign (int32 key)", "category": "go_map"},
    "runtime.mapassign_fast64": {"lib": "go-runtime", "purpose": "fast map assign (int64 key)", "category": "go_map"},
    "runtime.mapassign_faststr": {"lib": "go-runtime", "purpose": "fast map assign (string key)", "category": "go_map"},
    "runtime.mapdelete_fast32": {"lib": "go-runtime", "purpose": "fast map delete (int32 key)", "category": "go_map"},
    "runtime.mapdelete_fast64": {"lib": "go-runtime", "purpose": "fast map delete (int64 key)", "category": "go_map"},
    "runtime.mapdelete_faststr": {"lib": "go-runtime", "purpose": "fast map delete (string key)", "category": "go_map"},
    "runtime.mapiterinit": {"lib": "go-runtime", "purpose": "initialize map iterator", "category": "go_map"},
    "runtime.mapiternext": {"lib": "go-runtime", "purpose": "advance map iterator", "category": "go_map"},

    # --- runtime: type assertion / interface ---
    "runtime.assertI2I": {"lib": "go-runtime", "purpose": "interface-to-interface type assertion", "category": "go_runtime"},
    "runtime.assertI2I2": {"lib": "go-runtime", "purpose": "interface-to-interface (comma-ok)", "category": "go_runtime"},
    "runtime.assertE2I": {"lib": "go-runtime", "purpose": "empty-to-interface type assertion", "category": "go_runtime"},
    "runtime.assertE2I2": {"lib": "go-runtime", "purpose": "empty-to-interface (comma-ok)", "category": "go_runtime"},
    "runtime.convI2I": {"lib": "go-runtime", "purpose": "convert between interface types", "category": "go_runtime"},

    # --- runtime: string operations ---
    "runtime.stringtoslicebyte": {"lib": "go-runtime", "purpose": "convert string to []byte", "category": "go_slice"},
    "runtime.slicebytetostringtmp": {"lib": "go-runtime", "purpose": "temporary []byte to string (no copy)", "category": "go_slice"},
    "runtime.concatstrings": {"lib": "go-runtime", "purpose": "concatenate strings", "category": "go_slice"},
    "runtime.rawstringtmp": {"lib": "go-runtime", "purpose": "create temporary raw string", "category": "go_slice"},

    # --- runtime: select ---
    "runtime.selectgo": {"lib": "go-runtime", "purpose": "Go select statement implementation", "category": "go_channel"},
    "runtime.selectnbsend": {"lib": "go-runtime", "purpose": "non-blocking channel send in select", "category": "go_channel"},
    "runtime.selectnbrecv": {"lib": "go-runtime", "purpose": "non-blocking channel receive in select", "category": "go_channel"},

    # --- runtime: defer ---
    "runtime.deferproc": {"lib": "go-runtime", "purpose": "register deferred function call", "category": "go_runtime"},
    "runtime.deferreturn": {"lib": "go-runtime", "purpose": "execute deferred function calls", "category": "go_runtime"},

    # --- runtime: memory internals ---
    "runtime.newobject": {"lib": "go-runtime", "purpose": "allocate new object on heap", "category": "go_memory"},
    "runtime.memmove": {"lib": "go-runtime", "purpose": "Go runtime memory move", "category": "go_memory"},
    "runtime.memclrNoHeapPointers": {"lib": "go-runtime", "purpose": "clear non-pointer memory", "category": "go_memory"},
    "runtime.memclrHasPointers": {"lib": "go-runtime", "purpose": "clear memory containing pointers", "category": "go_memory"},

    # --- fmt extended ---
    "fmt.Errorf": {"lib": "go-fmt", "purpose": "format error message", "category": "go_fmt"},
    "fmt.Sscanf": {"lib": "go-fmt", "purpose": "scan formatted string", "category": "go_fmt"},
    "fmt.Fprintln": {"lib": "go-fmt", "purpose": "print line to io.Writer", "category": "go_fmt"},
    "fmt.Fprint": {"lib": "go-fmt", "purpose": "print to io.Writer", "category": "go_fmt"},
    "fmt.Sprint": {"lib": "go-fmt", "purpose": "format to string", "category": "go_fmt"},
    "fmt.Sprintln": {"lib": "go-fmt", "purpose": "format line to string", "category": "go_fmt"},

    # --- os extended ---
    "os.OpenFile": {"lib": "go-os", "purpose": "open file with flags and permissions", "category": "go_os"},
    "os.Mkdir": {"lib": "go-os", "purpose": "create directory", "category": "go_os"},
    "os.MkdirAll": {"lib": "go-os", "purpose": "create directory tree", "category": "go_os"},
    "os.Remove": {"lib": "go-os", "purpose": "remove file or empty directory", "category": "go_os"},
    "os.RemoveAll": {"lib": "go-os", "purpose": "remove file/directory tree", "category": "go_os"},
    "os.Rename": {"lib": "go-os", "purpose": "rename file", "category": "go_os"},
    "os.Stat": {"lib": "go-os", "purpose": "get file info", "category": "go_os"},
    "os.Lstat": {"lib": "go-os", "purpose": "get file info (no follow symlink)", "category": "go_os"},
    "os.ReadFile": {"lib": "go-os", "purpose": "read entire file contents", "category": "go_os"},
    "os.WriteFile": {"lib": "go-os", "purpose": "write data to file", "category": "go_os"},
    "os.Executable": {"lib": "go-os", "purpose": "get path of current executable", "category": "go_os"},
    "os.Hostname": {"lib": "go-os", "purpose": "get system hostname", "category": "go_os"},
    "os.UserHomeDir": {"lib": "go-os", "purpose": "get user home directory", "category": "go_os"},
    "os.Setenv": {"lib": "go-os", "purpose": "set environment variable", "category": "go_os"},

    # --- io ---
    "io.Copy": {"lib": "go-io", "purpose": "copy from Reader to Writer", "category": "go_io"},
    "io.ReadAll": {"lib": "go-io", "purpose": "read all bytes from Reader", "category": "go_io"},
    "io.ReadFull": {"lib": "go-io", "purpose": "read exactly n bytes", "category": "go_io"},
    "io.WriteString": {"lib": "go-io", "purpose": "write string to Writer", "category": "go_io"},
    "io.Pipe": {"lib": "go-io", "purpose": "create in-memory pipe", "category": "go_io"},
    "io.NopCloser": {"lib": "go-io", "purpose": "wrap Reader with no-op Close", "category": "go_io"},

    # --- bufio ---
    "bufio.NewReader": {"lib": "go-bufio", "purpose": "create buffered Reader", "category": "go_io"},
    "bufio.NewWriter": {"lib": "go-bufio", "purpose": "create buffered Writer", "category": "go_io"},
    "bufio.NewScanner": {"lib": "go-bufio", "purpose": "create line scanner", "category": "go_io"},

    # --- strings ---
    "strings.Contains": {"lib": "go-strings", "purpose": "check if string contains substring", "category": "go_string"},
    "strings.HasPrefix": {"lib": "go-strings", "purpose": "check string prefix", "category": "go_string"},
    "strings.HasSuffix": {"lib": "go-strings", "purpose": "check string suffix", "category": "go_string"},
    "strings.Split": {"lib": "go-strings", "purpose": "split string by separator", "category": "go_string"},
    "strings.Join": {"lib": "go-strings", "purpose": "join strings with separator", "category": "go_string"},
    "strings.Replace": {"lib": "go-strings", "purpose": "replace substring occurrences", "category": "go_string"},
    "strings.TrimSpace": {"lib": "go-strings", "purpose": "trim leading/trailing whitespace", "category": "go_string"},
    "strings.ToLower": {"lib": "go-strings", "purpose": "convert string to lowercase", "category": "go_string"},
    "strings.ToUpper": {"lib": "go-strings", "purpose": "convert string to uppercase", "category": "go_string"},
    "strings.NewReader": {"lib": "go-strings", "purpose": "create Reader from string", "category": "go_string"},

    # --- strconv ---
    "strconv.Itoa": {"lib": "go-strconv", "purpose": "integer to ASCII string", "category": "go_string"},
    "strconv.Atoi": {"lib": "go-strconv", "purpose": "ASCII string to integer", "category": "go_string"},
    "strconv.FormatInt": {"lib": "go-strconv", "purpose": "format int64 to string", "category": "go_string"},
    "strconv.ParseInt": {"lib": "go-strconv", "purpose": "parse string to int64", "category": "go_string"},
    "strconv.ParseFloat": {"lib": "go-strconv", "purpose": "parse string to float", "category": "go_string"},
    "strconv.FormatFloat": {"lib": "go-strconv", "purpose": "format float to string", "category": "go_string"},

    # --- bytes ---
    "bytes.Contains": {"lib": "go-bytes", "purpose": "check if byte slice contains pattern", "category": "go_string"},
    "bytes.Equal": {"lib": "go-bytes", "purpose": "compare byte slices for equality", "category": "go_string"},
    "bytes.NewBuffer": {"lib": "go-bytes", "purpose": "create byte buffer from initial data", "category": "go_string"},
    "bytes.NewReader": {"lib": "go-bytes", "purpose": "create Reader from byte slice", "category": "go_string"},

    # --- net extended ---
    "net.DialTimeout": {"lib": "go-net", "purpose": "connect with timeout", "category": "go_net"},
    "net.LookupHost": {"lib": "go-net", "purpose": "DNS hostname lookup", "category": "go_net"},
    "net.LookupAddr": {"lib": "go-net", "purpose": "reverse DNS lookup", "category": "go_net"},
    "net.LookupIP": {"lib": "go-net", "purpose": "lookup IP addresses for host", "category": "go_net"},
    "net.JoinHostPort": {"lib": "go-net", "purpose": "join host and port strings", "category": "go_net"},
    "net.SplitHostPort": {"lib": "go-net", "purpose": "split host:port string", "category": "go_net"},
    "net.ParseCIDR": {"lib": "go-net", "purpose": "parse CIDR notation address", "category": "go_net"},
    "net.ParseIP": {"lib": "go-net", "purpose": "parse IP address string", "category": "go_net"},
    "net.(*TCPListener).Accept": {"lib": "go-net", "purpose": "accept TCP connection", "category": "go_net"},
    "net.(*UDPConn).ReadFromUDP": {"lib": "go-net", "purpose": "read UDP datagram", "category": "go_net"},
    "net.(*UDPConn).WriteToUDP": {"lib": "go-net", "purpose": "write UDP datagram", "category": "go_net"},

    # --- net/http ---
    "net/http.ListenAndServe": {"lib": "go-net-http", "purpose": "start HTTP server", "category": "go_http"},
    "net/http.ListenAndServeTLS": {"lib": "go-net-http", "purpose": "start HTTPS server", "category": "go_http"},
    "net/http.Get": {"lib": "go-net-http", "purpose": "HTTP GET request", "category": "go_http"},
    "net/http.Post": {"lib": "go-net-http", "purpose": "HTTP POST request", "category": "go_http"},
    "net/http.NewRequest": {"lib": "go-net-http", "purpose": "create HTTP request", "category": "go_http"},
    "net/http.HandleFunc": {"lib": "go-net-http", "purpose": "register HTTP handler function", "category": "go_http"},
    "net/http.Handle": {"lib": "go-net-http", "purpose": "register HTTP handler", "category": "go_http"},
    "net/http.Redirect": {"lib": "go-net-http", "purpose": "HTTP redirect response", "category": "go_http"},
    "net/http.Error": {"lib": "go-net-http", "purpose": "HTTP error response", "category": "go_http"},
    "net/http.ServeFile": {"lib": "go-net-http", "purpose": "serve file over HTTP", "category": "go_http"},

    # --- encoding/json ---
    "encoding/json.Marshal": {"lib": "go-json", "purpose": "JSON marshal (struct to bytes)", "category": "go_json"},
    "encoding/json.Unmarshal": {"lib": "go-json", "purpose": "JSON unmarshal (bytes to struct)", "category": "go_json"},
    "encoding/json.NewDecoder": {"lib": "go-json", "purpose": "create streaming JSON decoder", "category": "go_json"},
    "encoding/json.NewEncoder": {"lib": "go-json", "purpose": "create streaming JSON encoder", "category": "go_json"},

    # --- encoding/base64 ---
    "encoding/base64.StdEncoding.EncodeToString": {"lib": "go-base64", "purpose": "base64 encode to string", "category": "go_encoding"},
    "encoding/base64.StdEncoding.DecodeString": {"lib": "go-base64", "purpose": "base64 decode from string", "category": "go_encoding"},

    # --- crypto ---
    "crypto/tls.Dial": {"lib": "go-crypto", "purpose": "TLS dial connection", "category": "go_crypto"},
    "crypto/sha256.Sum256": {"lib": "go-crypto", "purpose": "SHA-256 hash computation", "category": "go_crypto"},
    "crypto/sha256.New": {"lib": "go-crypto", "purpose": "create new SHA-256 hash", "category": "go_crypto"},
    "crypto/md5.Sum": {"lib": "go-crypto", "purpose": "MD5 hash computation", "category": "go_crypto"},
    "crypto/aes.NewCipher": {"lib": "go-crypto", "purpose": "create AES cipher block", "category": "go_crypto"},
    "crypto/rand.Read": {"lib": "go-crypto", "purpose": "read cryptographic random bytes", "category": "go_crypto"},
    "crypto/rsa.GenerateKey": {"lib": "go-crypto", "purpose": "generate RSA key pair", "category": "go_crypto"},
    "crypto/rsa.EncryptPKCS1v15": {"lib": "go-crypto", "purpose": "RSA PKCS#1 v1.5 encrypt", "category": "go_crypto"},
    "crypto/rsa.DecryptPKCS1v15": {"lib": "go-crypto", "purpose": "RSA PKCS#1 v1.5 decrypt", "category": "go_crypto"},
    "crypto/x509.ParseCertificate": {"lib": "go-crypto", "purpose": "parse X.509 certificate", "category": "go_crypto"},

    # --- sync extended ---
    "sync.(*RWMutex).RLock": {"lib": "go-sync", "purpose": "acquire read lock", "category": "go_sync"},
    "sync.(*RWMutex).RUnlock": {"lib": "go-sync", "purpose": "release read lock", "category": "go_sync"},
    "sync.(*RWMutex).Lock": {"lib": "go-sync", "purpose": "acquire write lock", "category": "go_sync"},
    "sync.(*RWMutex).Unlock": {"lib": "go-sync", "purpose": "release write lock", "category": "go_sync"},
    "sync.(*WaitGroup).Done": {"lib": "go-sync", "purpose": "decrement WaitGroup counter", "category": "go_sync"},
    "sync.(*Once).Do": {"lib": "go-sync", "purpose": "execute function exactly once", "category": "go_sync"},
    "sync.(*Pool).Get": {"lib": "go-sync", "purpose": "get item from sync pool", "category": "go_sync"},
    "sync.(*Pool).Put": {"lib": "go-sync", "purpose": "return item to sync pool", "category": "go_sync"},
    "sync.(*Map).Load": {"lib": "go-sync", "purpose": "load value from concurrent map", "category": "go_sync"},
    "sync.(*Map).Store": {"lib": "go-sync", "purpose": "store value in concurrent map", "category": "go_sync"},
    "sync.(*Map).Delete": {"lib": "go-sync", "purpose": "delete from concurrent map", "category": "go_sync"},
    "sync.(*Map).Range": {"lib": "go-sync", "purpose": "iterate concurrent map", "category": "go_sync"},
    "sync.(*Cond).Wait": {"lib": "go-sync", "purpose": "wait on condition variable", "category": "go_sync"},
    "sync.(*Cond).Signal": {"lib": "go-sync", "purpose": "signal one waiter", "category": "go_sync"},
    "sync.(*Cond).Broadcast": {"lib": "go-sync", "purpose": "signal all waiters", "category": "go_sync"},

    # --- context ---
    "context.Background": {"lib": "go-context", "purpose": "root context", "category": "go_context"},
    "context.TODO": {"lib": "go-context", "purpose": "placeholder context", "category": "go_context"},
    "context.WithCancel": {"lib": "go-context", "purpose": "create cancellable context", "category": "go_context"},
    "context.WithTimeout": {"lib": "go-context", "purpose": "create context with timeout", "category": "go_context"},
    "context.WithDeadline": {"lib": "go-context", "purpose": "create context with deadline", "category": "go_context"},
    "context.WithValue": {"lib": "go-context", "purpose": "create context with value", "category": "go_context"},

    # --- errors ---
    "errors.New": {"lib": "go-errors", "purpose": "create new error value", "category": "go_error"},
    "errors.Is": {"lib": "go-errors", "purpose": "check error chain for match", "category": "go_error"},
    "errors.As": {"lib": "go-errors", "purpose": "extract typed error from chain", "category": "go_error"},
    "errors.Unwrap": {"lib": "go-errors", "purpose": "unwrap error one level", "category": "go_error"},

    # --- path/filepath ---
    "path/filepath.Join": {"lib": "go-filepath", "purpose": "join path elements", "category": "go_os"},
    "path/filepath.Dir": {"lib": "go-filepath", "purpose": "get directory component", "category": "go_os"},
    "path/filepath.Base": {"lib": "go-filepath", "purpose": "get last path element", "category": "go_os"},
    "path/filepath.Ext": {"lib": "go-filepath", "purpose": "get file extension", "category": "go_os"},
    "path/filepath.Abs": {"lib": "go-filepath", "purpose": "get absolute path", "category": "go_os"},
    "path/filepath.Walk": {"lib": "go-filepath", "purpose": "walk directory tree", "category": "go_os"},
    "path/filepath.WalkDir": {"lib": "go-filepath", "purpose": "walk directory tree (efficient)", "category": "go_os"},
    "path/filepath.Glob": {"lib": "go-filepath", "purpose": "glob pattern matching", "category": "go_os"},

    # --- regexp ---
    "regexp.Compile": {"lib": "go-regexp", "purpose": "compile regular expression", "category": "go_regex"},
    "regexp.MustCompile": {"lib": "go-regexp", "purpose": "compile regex (panic on error)", "category": "go_regex"},
    "regexp.MatchString": {"lib": "go-regexp", "purpose": "test if string matches regex", "category": "go_regex"},

    # --- sort ---
    "sort.Slice": {"lib": "go-sort", "purpose": "sort slice with less function", "category": "go_sort"},
    "sort.SliceStable": {"lib": "go-sort", "purpose": "stable sort slice", "category": "go_sort"},
    "sort.Strings": {"lib": "go-sort", "purpose": "sort string slice", "category": "go_sort"},
    "sort.Ints": {"lib": "go-sort", "purpose": "sort int slice", "category": "go_sort"},
    "sort.Search": {"lib": "go-sort", "purpose": "binary search", "category": "go_sort"},

    # --- log ---
    "log.Fatal": {"lib": "go-log", "purpose": "log + os.Exit(1)", "category": "go_log"},
    "log.Fatalf": {"lib": "go-log", "purpose": "formatted log + exit", "category": "go_log"},
    "log.Panic": {"lib": "go-log", "purpose": "log + panic", "category": "go_log"},
    "log.Printf": {"lib": "go-log", "purpose": "formatted log output", "category": "go_log"},
    "log.Println": {"lib": "go-log", "purpose": "log line output", "category": "go_log"},

    # --- time ---
    "time.Now": {"lib": "go-time", "purpose": "get current time", "category": "go_time"},
    "time.Sleep": {"lib": "go-time", "purpose": "pause goroutine for duration", "category": "go_time"},
    "time.After": {"lib": "go-time", "purpose": "channel send after duration", "category": "go_time"},
    "time.Since": {"lib": "go-time", "purpose": "time elapsed since given time", "category": "go_time"},
    "time.NewTicker": {"lib": "go-time", "purpose": "create periodic ticker", "category": "go_time"},
    "time.NewTimer": {"lib": "go-time", "purpose": "create one-shot timer", "category": "go_time"},
    "time.Parse": {"lib": "go-time", "purpose": "parse time string", "category": "go_time"},

    # --- exec ---
    "os/exec.Command": {"lib": "go-exec", "purpose": "create command for execution", "category": "go_exec"},
    "os/exec.(*Cmd).Run": {"lib": "go-exec", "purpose": "run command and wait", "category": "go_exec"},
    "os/exec.(*Cmd).Output": {"lib": "go-exec", "purpose": "run command and capture stdout", "category": "go_exec"},
    "os/exec.(*Cmd).Start": {"lib": "go-exec", "purpose": "start command asynchronously", "category": "go_exec"},
    "os/exec.(*Cmd).Wait": {"lib": "go-exec", "purpose": "wait for started command", "category": "go_exec"},
    "os/exec.(*Cmd).CombinedOutput": {"lib": "go-exec", "purpose": "run and capture stdout+stderr", "category": "go_exec"},

    # --- database/sql ---
    "database/sql.Open": {"lib": "go-sql", "purpose": "open database connection pool", "category": "go_db"},
    "database/sql.(*DB).Query": {"lib": "go-sql", "purpose": "execute query returning rows", "category": "go_db"},
    "database/sql.(*DB).QueryRow": {"lib": "go-sql", "purpose": "execute query returning one row", "category": "go_db"},
    "database/sql.(*DB).Exec": {"lib": "go-sql", "purpose": "execute non-query statement", "category": "go_db"},
    "database/sql.(*DB).Prepare": {"lib": "go-sql", "purpose": "prepare SQL statement", "category": "go_db"},
    "database/sql.(*DB).Begin": {"lib": "go-sql", "purpose": "begin database transaction", "category": "go_db"},
    "database/sql.(*Tx).Commit": {"lib": "go-sql", "purpose": "commit transaction", "category": "go_db"},
    "database/sql.(*Tx).Rollback": {"lib": "go-sql", "purpose": "rollback transaction", "category": "go_db"},
    "database/sql.(*Rows).Scan": {"lib": "go-sql", "purpose": "scan row values into variables", "category": "go_db"},
    "database/sql.(*Rows).Next": {"lib": "go-sql", "purpose": "advance to next row", "category": "go_db"},
    "database/sql.(*Rows).Close": {"lib": "go-sql", "purpose": "close row iterator", "category": "go_db"},
}

# -------------------------------------------------------------------------
# CPython embedded C API (76 entry) - Interpreter, Object protocol, Reference
# counting, Module, Types (int/float/str/bytes), Container types, Error
# handling, GIL, Arg parsing. Kaynak: signature_db.py satir 6126-6220.
# -------------------------------------------------------------------------
_PYTHON_CAPI_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- Interpreter ---
    "Py_Initialize": {"lib": "python", "purpose": "initialize Python interpreter", "category": "python"},
    "Py_InitializeEx": {"lib": "python", "purpose": "initialize with signal config", "category": "python"},
    "Py_Finalize": {"lib": "python", "purpose": "finalize Python interpreter", "category": "python"},
    "Py_FinalizeEx": {"lib": "python", "purpose": "finalize with status return", "category": "python"},
    "Py_IsInitialized": {"lib": "python", "purpose": "check if interpreter initialized", "category": "python"},
    "PyRun_SimpleString": {"lib": "python", "purpose": "execute Python string", "category": "python"},
    "PyRun_SimpleFile": {"lib": "python", "purpose": "execute Python file", "category": "python"},
    "PyRun_String": {"lib": "python", "purpose": "execute string and return result", "category": "python"},
    "Py_CompileString": {"lib": "python", "purpose": "compile Python source to code object", "category": "python"},
    "PyEval_EvalCode": {"lib": "python", "purpose": "evaluate compiled code object", "category": "python"},

    # --- Object protocol ---
    "PyObject_CallObject": {"lib": "python", "purpose": "call Python callable with args tuple", "category": "python"},
    "PyObject_CallFunction": {"lib": "python", "purpose": "call Python callable with format args", "category": "python"},
    "PyObject_CallMethod": {"lib": "python", "purpose": "call method on Python object", "category": "python"},
    "PyObject_GetAttrString": {"lib": "python", "purpose": "get attribute by name", "category": "python"},
    "PyObject_SetAttrString": {"lib": "python", "purpose": "set attribute by name", "category": "python"},
    "PyObject_HasAttrString": {"lib": "python", "purpose": "check attribute exists", "category": "python"},
    "PyObject_Str": {"lib": "python", "purpose": "str() on Python object", "category": "python"},
    "PyObject_Repr": {"lib": "python", "purpose": "repr() on Python object", "category": "python"},
    "PyObject_IsTrue": {"lib": "python", "purpose": "bool() on Python object", "category": "python"},
    "PyObject_Length": {"lib": "python", "purpose": "len() on Python object", "category": "python"},
    "PyObject_GetItem": {"lib": "python", "purpose": "subscript operator obj[key]", "category": "python"},
    "PyObject_SetItem": {"lib": "python", "purpose": "subscript assignment obj[key]=val", "category": "python"},
    "PyObject_RichCompare": {"lib": "python", "purpose": "rich comparison (==, <, > etc)", "category": "python"},

    # --- Reference counting ---
    "Py_IncRef": {"lib": "python", "purpose": "increment reference count", "category": "python"},
    "Py_DecRef": {"lib": "python", "purpose": "decrement reference count", "category": "python"},
    "Py_XINCREF": {"lib": "python", "purpose": "increment refcount (NULL-safe)", "category": "python"},
    "Py_XDECREF": {"lib": "python", "purpose": "decrement refcount (NULL-safe)", "category": "python"},

    # --- Module ---
    "PyImport_ImportModule": {"lib": "python", "purpose": "import Python module", "category": "python"},
    "PyImport_AddModule": {"lib": "python", "purpose": "get or create module", "category": "python"},
    "PyModule_GetDict": {"lib": "python", "purpose": "get module's __dict__", "category": "python"},
    "PyModule_Create2": {"lib": "python", "purpose": "create extension module", "category": "python"},

    # --- Types: int, float, str, bytes ---
    "PyLong_FromLong": {"lib": "python", "purpose": "create Python int from C long", "category": "python"},
    "PyLong_AsLong": {"lib": "python", "purpose": "convert Python int to C long", "category": "python"},
    "PyLong_FromLongLong": {"lib": "python", "purpose": "create Python int from C long long", "category": "python"},
    "PyFloat_FromDouble": {"lib": "python", "purpose": "create Python float from C double", "category": "python"},
    "PyFloat_AsDouble": {"lib": "python", "purpose": "convert Python float to C double", "category": "python"},
    "PyUnicode_FromString": {"lib": "python", "purpose": "create Python str from C string", "category": "python"},
    "PyUnicode_AsUTF8": {"lib": "python", "purpose": "get UTF-8 from Python str", "category": "python"},
    "PyUnicode_FromFormat": {"lib": "python", "purpose": "create str from format string", "category": "python"},
    "PyBytes_FromString": {"lib": "python", "purpose": "create bytes from C string", "category": "python"},
    "PyBytes_FromStringAndSize": {"lib": "python", "purpose": "create bytes with size", "category": "python"},
    "PyBytes_AsString": {"lib": "python", "purpose": "get C char* from bytes", "category": "python"},
    "PyBool_FromLong": {"lib": "python", "purpose": "create Python bool from C long", "category": "python"},

    # --- Container types ---
    "PyList_New": {"lib": "python", "purpose": "create new Python list", "category": "python"},
    "PyList_Append": {"lib": "python", "purpose": "append to Python list", "category": "python"},
    "PyList_GetItem": {"lib": "python", "purpose": "get list item (borrowed ref)", "category": "python"},
    "PyList_SetItem": {"lib": "python", "purpose": "set list item (steals ref)", "category": "python"},
    "PyList_Size": {"lib": "python", "purpose": "get list length", "category": "python"},
    "PyDict_New": {"lib": "python", "purpose": "create new Python dict", "category": "python"},
    "PyDict_SetItemString": {"lib": "python", "purpose": "set dict item by string key", "category": "python"},
    "PyDict_GetItemString": {"lib": "python", "purpose": "get dict item by string key", "category": "python"},
    "PyDict_SetItem": {"lib": "python", "purpose": "set dict item", "category": "python"},
    "PyDict_GetItem": {"lib": "python", "purpose": "get dict item (borrowed ref)", "category": "python"},
    "PyDict_Keys": {"lib": "python", "purpose": "get dict keys list", "category": "python"},
    "PyDict_Size": {"lib": "python", "purpose": "get dict size", "category": "python"},
    "PyTuple_New": {"lib": "python", "purpose": "create new Python tuple", "category": "python"},
    "PyTuple_SetItem": {"lib": "python", "purpose": "set tuple item (steals ref)", "category": "python"},
    "PyTuple_GetItem": {"lib": "python", "purpose": "get tuple item (borrowed ref)", "category": "python"},
    "PyTuple_Size": {"lib": "python", "purpose": "get tuple length", "category": "python"},
    "PySet_New": {"lib": "python", "purpose": "create new Python set", "category": "python"},
    "PySet_Add": {"lib": "python", "purpose": "add item to set", "category": "python"},

    # --- Error handling ---
    "PyErr_SetString": {"lib": "python", "purpose": "set exception with message", "category": "python"},
    "PyErr_Occurred": {"lib": "python", "purpose": "check if exception is set", "category": "python"},
    "PyErr_Clear": {"lib": "python", "purpose": "clear current exception", "category": "python"},
    "PyErr_Print": {"lib": "python", "purpose": "print exception to stderr", "category": "python"},
    "PyErr_Fetch": {"lib": "python", "purpose": "fetch current exception", "category": "python"},
    "PyErr_Restore": {"lib": "python", "purpose": "restore exception state", "category": "python"},
    "PyErr_Format": {"lib": "python", "purpose": "set exception with formatted message", "category": "python"},
    "PyErr_NoMemory": {"lib": "python", "purpose": "set MemoryError exception", "category": "python"},

    # --- GIL ---
    "PyGILState_Ensure": {"lib": "python", "purpose": "acquire GIL and return state", "category": "python"},
    "PyGILState_Release": {"lib": "python", "purpose": "release GIL", "category": "python"},
    "PyEval_SaveThread": {"lib": "python", "purpose": "release GIL (Py_BEGIN_ALLOW_THREADS)", "category": "python"},
    "PyEval_RestoreThread": {"lib": "python", "purpose": "acquire GIL (Py_END_ALLOW_THREADS)", "category": "python"},

    # --- Arg parsing ---
    "PyArg_ParseTuple": {"lib": "python", "purpose": "parse positional args tuple", "category": "python"},
    "PyArg_ParseTupleAndKeywords": {"lib": "python", "purpose": "parse args and kwargs", "category": "python"},
    "Py_BuildValue": {"lib": "python", "purpose": "build Python value from C values", "category": "python"},
}

# -------------------------------------------------------------------------
# Java JNI (50 entry) - JVM yonetimi, sinif/method/field id, method cagrilari,
# string/array, global/local refs, exception handling, RegisterNatives, monitor
# enter/exit, thread attach. Kaynak: signature_db.py satir 6228-6280.
# -------------------------------------------------------------------------
_JAVA_JNI_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "JNI_CreateJavaVM": {"lib": "jni", "purpose": "create Java Virtual Machine", "category": "java"},
    "JNI_GetCreatedJavaVMs": {"lib": "jni", "purpose": "get list of created JVMs", "category": "java"},
    "JNI_GetDefaultJavaVMInitArgs": {"lib": "jni", "purpose": "get default JVM init args", "category": "java"},
    "JNI_OnLoad": {"lib": "jni", "purpose": "native library loaded by JVM", "category": "java"},
    "JNI_OnUnload": {"lib": "jni", "purpose": "native library unloaded by JVM", "category": "java"},
    # Env functions (commonly resolved via function pointer table)
    "FindClass": {"lib": "jni", "purpose": "find Java class by name", "category": "java"},
    "GetMethodID": {"lib": "jni", "purpose": "get Java method ID", "category": "java"},
    "GetStaticMethodID": {"lib": "jni", "purpose": "get static Java method ID", "category": "java"},
    "GetFieldID": {"lib": "jni", "purpose": "get Java field ID", "category": "java"},
    "GetStaticFieldID": {"lib": "jni", "purpose": "get static Java field ID", "category": "java"},
    "CallObjectMethod": {"lib": "jni", "purpose": "call Java object method", "category": "java"},
    "CallVoidMethod": {"lib": "jni", "purpose": "call Java void method", "category": "java"},
    "CallIntMethod": {"lib": "jni", "purpose": "call Java int method", "category": "java"},
    "CallBooleanMethod": {"lib": "jni", "purpose": "call Java boolean method", "category": "java"},
    "CallStaticObjectMethod": {"lib": "jni", "purpose": "call static Java method (Object)", "category": "java"},
    "CallStaticVoidMethod": {"lib": "jni", "purpose": "call static Java void method", "category": "java"},
    "NewObject": {"lib": "jni", "purpose": "create new Java object", "category": "java"},
    "NewStringUTF": {"lib": "jni", "purpose": "create Java string from UTF-8", "category": "java"},
    "GetStringUTFChars": {"lib": "jni", "purpose": "get UTF-8 chars from Java string", "category": "java"},
    "ReleaseStringUTFChars": {"lib": "jni", "purpose": "release UTF-8 chars", "category": "java"},
    "GetArrayLength": {"lib": "jni", "purpose": "get Java array length", "category": "java"},
    "GetByteArrayElements": {"lib": "jni", "purpose": "get Java byte array elements", "category": "java"},
    "ReleaseByteArrayElements": {"lib": "jni", "purpose": "release byte array elements", "category": "java"},
    "NewByteArray": {"lib": "jni", "purpose": "create Java byte array", "category": "java"},
    "SetByteArrayRegion": {"lib": "jni", "purpose": "copy bytes into Java array", "category": "java"},
    "GetByteArrayRegion": {"lib": "jni", "purpose": "copy bytes from Java array", "category": "java"},
    "NewGlobalRef": {"lib": "jni", "purpose": "create global JNI reference", "category": "java"},
    "DeleteGlobalRef": {"lib": "jni", "purpose": "delete global JNI reference", "category": "java"},
    "NewLocalRef": {"lib": "jni", "purpose": "create local JNI reference", "category": "java"},
    "DeleteLocalRef": {"lib": "jni", "purpose": "delete local JNI reference", "category": "java"},
    "ExceptionCheck": {"lib": "jni", "purpose": "check for pending Java exception", "category": "java"},
    "ExceptionDescribe": {"lib": "jni", "purpose": "print Java exception to stderr", "category": "java"},
    "ExceptionClear": {"lib": "jni", "purpose": "clear pending Java exception", "category": "java"},
    "ThrowNew": {"lib": "jni", "purpose": "throw new Java exception", "category": "java"},
    "RegisterNatives": {"lib": "jni", "purpose": "register native methods with class", "category": "java"},
    "UnregisterNatives": {"lib": "jni", "purpose": "unregister native methods", "category": "java"},
    "GetObjectClass": {"lib": "jni", "purpose": "get class of Java object", "category": "java"},
    "IsInstanceOf": {"lib": "jni", "purpose": "check Java instanceof", "category": "java"},
    "MonitorEnter": {"lib": "jni", "purpose": "enter Java synchronized block", "category": "java"},
    "MonitorExit": {"lib": "jni", "purpose": "exit Java synchronized block", "category": "java"},
    "GetJavaVM": {"lib": "jni", "purpose": "get JavaVM interface pointer", "category": "java"},
    "AttachCurrentThread": {"lib": "jni", "purpose": "attach native thread to JVM", "category": "java"},
    "DetachCurrentThread": {"lib": "jni", "purpose": "detach native thread from JVM", "category": "java"},
    "GetEnv": {"lib": "jni", "purpose": "get JNI environment for current thread", "category": "java"},
    "GetObjectField": {"lib": "jni", "purpose": "get Java object field value", "category": "java"},
    "SetObjectField": {"lib": "jni", "purpose": "set Java object field value", "category": "java"},
    "GetIntField": {"lib": "jni", "purpose": "get Java int field value", "category": "java"},
    "SetIntField": {"lib": "jni", "purpose": "set Java int field value", "category": "java"},
    "GetLongField": {"lib": "jni", "purpose": "get Java long field value", "category": "java"},
    "SetLongField": {"lib": "jni", "purpose": "set Java long field value", "category": "java"},
}

# -------------------------------------------------------------------------
# .NET CLR / Mono / hostfxr / IL2CPP (58 entry) - CoreCLR hosting, Mono
# embedding, .NET hosting API (newer), Unity IL2CPP runtime.
# Kaynak: signature_db.py satir 6288-6354.
# -------------------------------------------------------------------------
_DOTNET_CLR_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- CoreCLR hosting ---
    "coreclr_initialize": {"lib": "coreclr", "purpose": "initialize .NET CoreCLR runtime", "category": "dotnet"},
    "coreclr_create_delegate": {"lib": "coreclr", "purpose": "create delegate to managed method", "category": "dotnet"},
    "coreclr_execute_assembly": {"lib": "coreclr", "purpose": "execute managed assembly entrypoint", "category": "dotnet"},
    "coreclr_shutdown": {"lib": "coreclr", "purpose": "shutdown CoreCLR runtime", "category": "dotnet"},
    "coreclr_shutdown_2": {"lib": "coreclr", "purpose": "shutdown with exit code", "category": "dotnet"},

    # --- Mono embedding ---
    "mono_jit_init": {"lib": "mono", "purpose": "initialize Mono JIT engine", "category": "dotnet"},
    "mono_jit_cleanup": {"lib": "mono", "purpose": "cleanup Mono JIT", "category": "dotnet"},
    "mono_domain_create_appdomain": {"lib": "mono", "purpose": "create Mono AppDomain", "category": "dotnet"},
    "mono_domain_unload": {"lib": "mono", "purpose": "unload Mono AppDomain", "category": "dotnet"},
    "mono_assembly_open": {"lib": "mono", "purpose": "load .NET assembly", "category": "dotnet"},
    "mono_assembly_get_image": {"lib": "mono", "purpose": "get image from assembly", "category": "dotnet"},
    "mono_class_from_name": {"lib": "mono", "purpose": "find managed class by name", "category": "dotnet"},
    "mono_class_get_method_from_name": {"lib": "mono", "purpose": "find method by name", "category": "dotnet"},
    "mono_runtime_invoke": {"lib": "mono", "purpose": "invoke managed method", "category": "dotnet"},
    "mono_object_new": {"lib": "mono", "purpose": "create managed object instance", "category": "dotnet"},
    "mono_runtime_object_init": {"lib": "mono", "purpose": "call managed constructor", "category": "dotnet"},
    "mono_string_new": {"lib": "mono", "purpose": "create managed string", "category": "dotnet"},
    "mono_string_to_utf8": {"lib": "mono", "purpose": "convert managed string to UTF-8", "category": "dotnet"},
    "mono_array_new": {"lib": "mono", "purpose": "create managed array", "category": "dotnet"},
    "mono_gchandle_new": {"lib": "mono", "purpose": "create GC handle for managed object", "category": "dotnet"},
    "mono_gchandle_free": {"lib": "mono", "purpose": "free GC handle", "category": "dotnet"},
    "mono_gchandle_get_target": {"lib": "mono", "purpose": "get object from GC handle", "category": "dotnet"},
    "mono_gc_collect": {"lib": "mono", "purpose": "trigger GC collection", "category": "dotnet"},
    "mono_thread_attach": {"lib": "mono", "purpose": "attach native thread to Mono runtime", "category": "dotnet"},
    "mono_thread_detach": {"lib": "mono", "purpose": "detach native thread from Mono", "category": "dotnet"},
    "mono_add_internal_call": {"lib": "mono", "purpose": "register native method as internal call", "category": "dotnet"},
    "mono_type_get_object": {"lib": "mono", "purpose": "get System.Type for mono type", "category": "dotnet"},
    "mono_field_get_value": {"lib": "mono", "purpose": "get field value from managed object", "category": "dotnet"},
    "mono_field_set_value": {"lib": "mono", "purpose": "set field value on managed object", "category": "dotnet"},
    "mono_property_get_value": {"lib": "mono", "purpose": "get property value", "category": "dotnet"},
    "mono_property_set_value": {"lib": "mono", "purpose": "set property value", "category": "dotnet"},
    "mono_raise_exception": {"lib": "mono", "purpose": "raise managed exception", "category": "dotnet"},
    "mono_error_init": {"lib": "mono", "purpose": "initialize error struct", "category": "dotnet"},
    "mono_error_ok": {"lib": "mono", "purpose": "check if error occurred", "category": "dotnet"},

    # --- .NET hosting API (newer) ---
    "hostfxr_initialize_for_runtime_config": {"lib": "hostfxr", "purpose": "initialize host with runtime config", "category": "dotnet"},
    "hostfxr_get_runtime_delegate": {"lib": "hostfxr", "purpose": "get runtime delegate function pointer", "category": "dotnet"},
    "hostfxr_close": {"lib": "hostfxr", "purpose": "close host context", "category": "dotnet"},
    "hostfxr_initialize_for_dotnet_command_line": {"lib": "hostfxr", "purpose": "initialize for CLI command", "category": "dotnet"},
    "hostfxr_run_app": {"lib": "hostfxr", "purpose": "run .NET application", "category": "dotnet"},
    "hostfxr_set_runtime_property_value": {"lib": "hostfxr", "purpose": "set runtime configuration property", "category": "dotnet"},

    # --- Unity / IL2CPP ---
    "il2cpp_init": {"lib": "il2cpp", "purpose": "initialize IL2CPP runtime (Unity)", "category": "dotnet"},
    "il2cpp_init_utf16": {"lib": "il2cpp", "purpose": "initialize IL2CPP (UTF-16 domain name)", "category": "dotnet"},
    "il2cpp_shutdown": {"lib": "il2cpp", "purpose": "shutdown IL2CPP runtime", "category": "dotnet"},
    "il2cpp_domain_get": {"lib": "il2cpp", "purpose": "get current IL2CPP domain", "category": "dotnet"},
    "il2cpp_domain_assembly_open": {"lib": "il2cpp", "purpose": "load assembly in IL2CPP domain", "category": "dotnet"},
    "il2cpp_class_from_name": {"lib": "il2cpp", "purpose": "find IL2CPP class by namespace/name", "category": "dotnet"},
    "il2cpp_class_get_method_from_name": {"lib": "il2cpp", "purpose": "find method in IL2CPP class", "category": "dotnet"},
    "il2cpp_runtime_invoke": {"lib": "il2cpp", "purpose": "invoke IL2CPP method", "category": "dotnet"},
    "il2cpp_object_new": {"lib": "il2cpp", "purpose": "create IL2CPP object", "category": "dotnet"},
    "il2cpp_string_new": {"lib": "il2cpp", "purpose": "create IL2CPP string", "category": "dotnet"},
    "il2cpp_string_chars": {"lib": "il2cpp", "purpose": "get chars from IL2CPP string", "category": "dotnet"},
    "il2cpp_array_new": {"lib": "il2cpp", "purpose": "create IL2CPP array", "category": "dotnet"},
    "il2cpp_field_get_value": {"lib": "il2cpp", "purpose": "get field value from IL2CPP object", "category": "dotnet"},
    "il2cpp_field_set_value": {"lib": "il2cpp", "purpose": "set field value on IL2CPP object", "category": "dotnet"},
    "il2cpp_gchandle_new": {"lib": "il2cpp", "purpose": "create IL2CPP GC handle", "category": "dotnet"},
    "il2cpp_gchandle_free": {"lib": "il2cpp", "purpose": "free IL2CPP GC handle", "category": "dotnet"},
    "il2cpp_thread_attach": {"lib": "il2cpp", "purpose": "attach thread to IL2CPP", "category": "dotnet"},
    "il2cpp_thread_detach": {"lib": "il2cpp", "purpose": "detach thread from IL2CPP", "category": "dotnet"},
}


# -------------------------------------------------------------------------

# Dispatcher hook - sigdb_builtin.get_category("...") bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur.
# -------------------------------------------------------------------------

SIGNATURES: dict[str, Any] = {
    "rust_stdlib_signatures": _RUST_STDLIB_SIGNATURES_DATA,
    "rust_ext_signatures": _RUST_EXT_SIGNATURES_DATA,
    "go_runtime_signatures": _GO_RUNTIME_SIGNATURES_DATA,
    "go_ext_signatures": _GO_EXT_SIGNATURES_DATA,
    "python_capi_signatures": _PYTHON_CAPI_SIGNATURES_DATA,
    "java_jni_signatures": _JAVA_JNI_SIGNATURES_DATA,
    "dotnet_clr_signatures": _DOTNET_CLR_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
