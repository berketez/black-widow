"""Modern runtime signatures (Rust + Go) — sig_db Faz 7 dalgasi.

2024-2026 doneminde yazilan modern malware ve commodity araclar buyuk
olcude Rust ve Go ile uretilmektedir. Bu modul her iki dilin core runtime
ve yaygin ekosistem sembollerini `signature_db.py` icine plug-in olarak
tasir. Veri `pe_runtime.py` pattern'ini birebir takip eder (SIGNATURES dict
+ override + fallback).

Iki alt veri kumesi:

  1. ``rust_runtime_signatures`` — Rust ekosisteminin modern / mangled ve
     demangled sembolleri. Kapsama: global allocator, panic/unwind, core::*
     demangled mangling prefix'leri, std::* alt modulleri, tokio async,
     reqwest/hyper HTTP, serde, clap/structopt CLI, aes/chacha20 crypto.
     Malware-specific framework (Sliver, BlackCat vb.) iceriK YOK — v1.13
     malware_signatures modulune birakilir.

  2. ``go_runtime_signatures`` — Go runtime/scheduler/GC, slice/map/channel
     helper'lari, goroutine yonetimi, tip/interface conversion, stdlib
     paket isimleri (net, crypto, encoding, fmt, os). Go mangling pattern'i
     `pkg.Name` ve `pkg.(*Type).Method` sekillerinde.

Toplam entry: ~230 (Rust ~90, Go ~140).

Cross-platform not: Rust/Go binary'ler Windows PE, Linux ELF, macOS Mach-O
her uc formatta da uretilir. Kategori etiketleri platform-bagimsiz
tutulmustur (``rust_*`` / ``go_*`` prefix'i); platform-specific filter
bunlari bloklamaz.

Cakisma / idempotency:
  - Mevcut ``_RUST_STDLIB_SIGNATURES`` / ``_GO_RUNTIME_SIGNATURES`` /
    ``_RUST_EXT_SIGNATURES`` / ``_GO_EXT_SIGNATURES`` dict'leri KORUNUR.
  - Bu modulde TEKRARLANAN bir anahtar varsa ayni ``lib`` / ``purpose``
    degerleri tasir (dict.update ile son yazan kalir, idempotent).
  - YENI anahtarlar buyuk olcude demangled ``core::*`` / ``std::*`` isim
    formlari ve acik crate icon anahtar kelimeleri (``tokio::runtime::Runtime::new``
    gibi) olarak eklenmistir.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Rust runtime signatures
# ---------------------------------------------------------------------------
# Kapsama:
#   - global allocator sembolleri (__rust_alloc ailesi)
#   - panic / unwinding (rust_panic, rust_eh_personality, _Unwind_Resume)
#   - core::* demangled isim prefix'leri (core::panicking, core::option,
#     core::result, core::iter, core::fmt)
#   - std::* demangled (std::io, std::fs, std::thread, std::sync,
#     std::collections, std::process, std::env, std::panic::catch_unwind)
#   - tokio async ekosistemi (Runtime::new, spawn, block_on, task::spawn)
#   - reqwest / hyper HTTP (Client::new, Client::get, Server::bind)
#   - serde ser/de (Serialize::serialize, Deserialize::deserialize)
#   - clap / structopt CLI parser
#   - aes / aes-gcm / chacha20 / chacha20poly1305 crypto crates
# Platform-bagimsiz: Rust binary her 3 platformda da gorulur.
# ---------------------------------------------------------------------------
_RUST_RUNTIME_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- Global allocator (no_std + std) ---
    "__rust_alloc": {"lib": "rust_std", "purpose": "Rust global allocator allocate", "category": "rust_runtime"},
    "__rust_dealloc": {"lib": "rust_std", "purpose": "Rust global allocator deallocate", "category": "rust_runtime"},
    "__rust_realloc": {"lib": "rust_std", "purpose": "Rust global allocator reallocate", "category": "rust_runtime"},
    "__rust_alloc_zeroed": {"lib": "rust_std", "purpose": "Rust global allocator zero-initialized alloc", "category": "rust_runtime"},
    "__rust_alloc_error_handler": {"lib": "rust_std", "purpose": "Rust allocation failure handler", "category": "rust_runtime"},
    "__rust_no_alloc_shim_is_unstable": {"lib": "rust_std", "purpose": "Rust alloc shim marker symbol", "category": "rust_runtime"},
    "__rust_probestack": {"lib": "rust_std", "purpose": "Rust stack probe helper", "category": "rust_runtime"},
    "__rust_start_panic": {"lib": "rust_std", "purpose": "Rust panic runtime start", "category": "rust_runtime"},
    "__rust_drop_panic": {"lib": "rust_std", "purpose": "Rust panic payload drop", "category": "rust_runtime"},
    "__rust_foreign_exception": {"lib": "rust_std", "purpose": "Rust foreign exception propagation", "category": "rust_runtime"},
    "__rg_alloc": {"lib": "rust_std", "purpose": "Rust custom allocator shim (alloc)", "category": "rust_runtime"},
    "__rg_dealloc": {"lib": "rust_std", "purpose": "Rust custom allocator shim (dealloc)", "category": "rust_runtime"},
    "__rg_realloc": {"lib": "rust_std", "purpose": "Rust custom allocator shim (realloc)", "category": "rust_runtime"},
    "__rg_alloc_zeroed": {"lib": "rust_std", "purpose": "Rust custom allocator shim (alloc_zeroed)", "category": "rust_runtime"},

    # --- Panic / unwinding ---
    "rust_panic": {"lib": "rust_std", "purpose": "Rust panic handler core entry", "category": "rust_runtime"},
    "rust_begin_unwind": {"lib": "rust_std", "purpose": "Rust panic unwinding entry point", "category": "rust_runtime"},
    "rust_eh_personality": {"lib": "rust_std", "purpose": "Rust exception personality (LSDA)", "category": "rust_runtime"},
    "rust_eh_unwind_resume": {"lib": "rust_std", "purpose": "Rust unwind resume trampoline", "category": "rust_runtime"},
    "_Unwind_Resume": {"lib": "rust_std", "purpose": "Itanium ABI unwind resume", "category": "rust_runtime"},
    "_Unwind_RaiseException": {"lib": "rust_std", "purpose": "Itanium ABI raise exception", "category": "rust_runtime"},
    "_Unwind_Backtrace": {"lib": "rust_std", "purpose": "Itanium ABI unwind backtrace", "category": "rust_runtime"},
    "_Unwind_DeleteException": {"lib": "rust_std", "purpose": "Itanium ABI delete exception", "category": "rust_runtime"},
    "_Unwind_GetIP": {"lib": "rust_std", "purpose": "Itanium ABI get instruction pointer", "category": "rust_runtime"},
    "_Unwind_GetRegionStart": {"lib": "rust_std", "purpose": "Itanium ABI get region start", "category": "rust_runtime"},
    "_Unwind_GetTextRelBase": {"lib": "rust_std", "purpose": "Itanium ABI get text-relative base", "category": "rust_runtime"},
    "_Unwind_GetDataRelBase": {"lib": "rust_std", "purpose": "Itanium ABI get data-relative base", "category": "rust_runtime"},
    "_Unwind_GetLanguageSpecificData": {"lib": "rust_std", "purpose": "Itanium ABI get LSDA", "category": "rust_runtime"},
    "_Unwind_SetIP": {"lib": "rust_std", "purpose": "Itanium ABI set instruction pointer", "category": "rust_runtime"},
    "_Unwind_SetGR": {"lib": "rust_std", "purpose": "Itanium ABI set general register", "category": "rust_runtime"},

    # --- core::panicking (demangled + mangled prefixes) ---
    "core::panicking::panic": {"lib": "rust_std", "purpose": "core::panicking::panic entry (const msg)", "category": "rust_runtime"},
    "core::panicking::panic_fmt": {"lib": "rust_std", "purpose": "core::panicking::panic_fmt (formatted)", "category": "rust_runtime"},
    "core::panicking::panic_bounds_check": {"lib": "rust_std", "purpose": "core::panicking::panic_bounds_check", "category": "rust_runtime"},
    "core::panicking::panic_nounwind": {"lib": "rust_std", "purpose": "core::panicking::panic_nounwind", "category": "rust_runtime"},
    "core::panicking::panic_no_catch_unwind": {"lib": "rust_std", "purpose": "core::panicking::panic_no_catch_unwind", "category": "rust_runtime"},
    "core::panicking::assert_failed": {"lib": "rust_std", "purpose": "core::panicking::assert_failed (assert!)", "category": "rust_runtime"},
    "core::panicking::panic_cannot_unwind": {"lib": "rust_std", "purpose": "core::panicking::panic_cannot_unwind", "category": "rust_runtime"},
    "_ZN4core9panicking5panic": {"lib": "rust_std", "purpose": "core::panicking::panic mangled", "category": "rust_runtime"},
    "_ZN4core9panicking9panic_fmt": {"lib": "rust_std", "purpose": "core::panicking::panic_fmt mangled", "category": "rust_runtime"},
    "_ZN4core9panicking18panic_bounds_check": {"lib": "rust_std", "purpose": "core::panicking::panic_bounds_check mangled", "category": "rust_runtime"},
    "_ZN4core9panicking13assert_failed": {"lib": "rust_std", "purpose": "core::panicking::assert_failed mangled", "category": "rust_runtime"},

    # --- core::option / core::result (ubiquitous in Rust binaries) ---
    "_ZN4core6option": {"lib": "rust_std", "purpose": "core::option::Option methods (mangled prefix)", "category": "rust_runtime"},
    "_ZN4core6result": {"lib": "rust_std", "purpose": "core::result::Result methods (mangled prefix)", "category": "rust_runtime"},
    "core::option::Option::unwrap": {"lib": "rust_std", "purpose": "Option::unwrap method", "category": "rust_runtime"},
    "core::option::Option::expect": {"lib": "rust_std", "purpose": "Option::expect method", "category": "rust_runtime"},
    "core::result::Result::unwrap": {"lib": "rust_std", "purpose": "Result::unwrap method", "category": "rust_runtime"},
    "core::result::Result::expect": {"lib": "rust_std", "purpose": "Result::expect method", "category": "rust_runtime"},
    "core::result::unwrap_failed": {"lib": "rust_std", "purpose": "Result unwrap panic helper", "category": "rust_runtime"},
    "core::option::expect_failed": {"lib": "rust_std", "purpose": "Option expect panic helper", "category": "rust_runtime"},

    # --- core::iter / core::fmt (mangled prefixes) ---
    "_ZN4core4iter": {"lib": "rust_std", "purpose": "core::iter iterator infrastructure (mangled)", "category": "rust_runtime"},
    "_ZN4core3fmt": {"lib": "rust_std", "purpose": "core::fmt formatting infrastructure (mangled)", "category": "rust_runtime"},
    "_ZN4core3fmt9Formatter": {"lib": "rust_std", "purpose": "core::fmt::Formatter methods (mangled)", "category": "rust_runtime"},
    "_ZN4core3fmt5Write": {"lib": "rust_std", "purpose": "core::fmt::Write trait (mangled)", "category": "rust_runtime"},
    "_ZN4core3ptr": {"lib": "rust_std", "purpose": "core::ptr raw pointer ops (mangled)", "category": "rust_runtime"},
    "_ZN4core3str": {"lib": "rust_std", "purpose": "core::str string slice methods (mangled)", "category": "rust_runtime"},
    "_ZN4core5slice": {"lib": "rust_std", "purpose": "core::slice methods (mangled)", "category": "rust_runtime"},
    "_ZN4core3ops": {"lib": "rust_std", "purpose": "core::ops operator traits (mangled)", "category": "rust_runtime"},
    "_ZN4core3mem": {"lib": "rust_std", "purpose": "core::mem memory ops (swap/drop) (mangled)", "category": "rust_runtime"},

    # --- std::io (demangled high-level) ---
    "std::io::stdin": {"lib": "rust_std", "purpose": "std::io::stdin handle", "category": "rust_runtime"},
    "std::io::stdout": {"lib": "rust_std", "purpose": "std::io::stdout handle", "category": "rust_runtime"},
    "std::io::stderr": {"lib": "rust_std", "purpose": "std::io::stderr handle", "category": "rust_runtime"},
    "std::io::Read::read": {"lib": "rust_std", "purpose": "std::io::Read::read trait method", "category": "rust_runtime"},
    "std::io::Write::write": {"lib": "rust_std", "purpose": "std::io::Write::write trait method", "category": "rust_runtime"},
    "std::io::Write::write_all": {"lib": "rust_std", "purpose": "std::io::Write::write_all", "category": "rust_runtime"},
    "std::io::Write::flush": {"lib": "rust_std", "purpose": "std::io::Write::flush", "category": "rust_runtime"},
    "std::io::BufReader::new": {"lib": "rust_std", "purpose": "std::io::BufReader::new", "category": "rust_runtime"},
    "std::io::BufWriter::new": {"lib": "rust_std", "purpose": "std::io::BufWriter::new", "category": "rust_runtime"},

    # --- std::fs (filesystem) ---
    "std::fs::File::open": {"lib": "rust_std", "purpose": "std::fs::File::open", "category": "rust_runtime"},
    "std::fs::File::create": {"lib": "rust_std", "purpose": "std::fs::File::create", "category": "rust_runtime"},
    "std::fs::read": {"lib": "rust_std", "purpose": "std::fs::read entire file", "category": "rust_runtime"},
    "std::fs::read_to_string": {"lib": "rust_std", "purpose": "std::fs::read_to_string", "category": "rust_runtime"},
    "std::fs::write": {"lib": "rust_std", "purpose": "std::fs::write entire buffer", "category": "rust_runtime"},
    "std::fs::remove_file": {"lib": "rust_std", "purpose": "std::fs::remove_file", "category": "rust_runtime"},
    "std::fs::rename": {"lib": "rust_std", "purpose": "std::fs::rename", "category": "rust_runtime"},
    "std::fs::create_dir": {"lib": "rust_std", "purpose": "std::fs::create_dir", "category": "rust_runtime"},
    "std::fs::create_dir_all": {"lib": "rust_std", "purpose": "std::fs::create_dir_all", "category": "rust_runtime"},
    "std::fs::read_dir": {"lib": "rust_std", "purpose": "std::fs::read_dir", "category": "rust_runtime"},

    # --- std::thread ---
    "std::thread::spawn": {"lib": "rust_std", "purpose": "std::thread::spawn", "category": "rust_runtime"},
    "std::thread::sleep": {"lib": "rust_std", "purpose": "std::thread::sleep", "category": "rust_runtime"},
    "std::thread::current": {"lib": "rust_std", "purpose": "std::thread::current handle", "category": "rust_runtime"},
    "std::thread::park": {"lib": "rust_std", "purpose": "std::thread::park", "category": "rust_runtime"},
    "std::thread::JoinHandle::join": {"lib": "rust_std", "purpose": "std::thread::JoinHandle::join", "category": "rust_runtime"},

    # --- std::sync (primitives) ---
    "std::sync::Mutex::new": {"lib": "rust_std", "purpose": "std::sync::Mutex::new", "category": "rust_runtime"},
    "std::sync::Mutex::lock": {"lib": "rust_std", "purpose": "std::sync::Mutex::lock", "category": "rust_runtime"},
    "std::sync::RwLock::new": {"lib": "rust_std", "purpose": "std::sync::RwLock::new", "category": "rust_runtime"},
    "std::sync::RwLock::read": {"lib": "rust_std", "purpose": "std::sync::RwLock::read", "category": "rust_runtime"},
    "std::sync::RwLock::write": {"lib": "rust_std", "purpose": "std::sync::RwLock::write", "category": "rust_runtime"},
    "std::sync::Arc::new": {"lib": "rust_std", "purpose": "std::sync::Arc::new", "category": "rust_runtime"},
    "std::sync::Arc::clone": {"lib": "rust_std", "purpose": "std::sync::Arc::clone", "category": "rust_runtime"},
    "std::sync::mpsc::channel": {"lib": "rust_std", "purpose": "std::sync::mpsc::channel", "category": "rust_runtime"},
    "std::sync::Once::call_once": {"lib": "rust_std", "purpose": "std::sync::Once::call_once", "category": "rust_runtime"},

    # --- std::collections ---
    "std::collections::HashMap::new": {"lib": "rust_std", "purpose": "HashMap::new", "category": "rust_runtime"},
    "std::collections::HashMap::insert": {"lib": "rust_std", "purpose": "HashMap::insert", "category": "rust_runtime"},
    "std::collections::HashMap::get": {"lib": "rust_std", "purpose": "HashMap::get", "category": "rust_runtime"},
    "std::collections::HashSet::new": {"lib": "rust_std", "purpose": "HashSet::new", "category": "rust_runtime"},
    "std::collections::BTreeMap::new": {"lib": "rust_std", "purpose": "BTreeMap::new", "category": "rust_runtime"},
    "std::collections::VecDeque::new": {"lib": "rust_std", "purpose": "VecDeque::new", "category": "rust_runtime"},

    # --- std::process ---
    "std::process::exit": {"lib": "rust_std", "purpose": "std::process::exit", "category": "rust_runtime"},
    "std::process::abort": {"lib": "rust_std", "purpose": "std::process::abort", "category": "rust_runtime"},
    "std::process::Command::new": {"lib": "rust_std", "purpose": "std::process::Command::new", "category": "rust_runtime"},
    "std::process::Command::spawn": {"lib": "rust_std", "purpose": "std::process::Command::spawn", "category": "rust_runtime"},
    "std::process::Command::output": {"lib": "rust_std", "purpose": "std::process::Command::output", "category": "rust_runtime"},
    "std::process::Command::arg": {"lib": "rust_std", "purpose": "std::process::Command::arg", "category": "rust_runtime"},

    # --- std::env ---
    "std::env::args": {"lib": "rust_std", "purpose": "std::env::args iterator", "category": "rust_runtime"},
    "std::env::var": {"lib": "rust_std", "purpose": "std::env::var (env read)", "category": "rust_runtime"},
    "std::env::set_var": {"lib": "rust_std", "purpose": "std::env::set_var", "category": "rust_runtime"},
    "std::env::remove_var": {"lib": "rust_std", "purpose": "std::env::remove_var", "category": "rust_runtime"},
    "std::env::current_dir": {"lib": "rust_std", "purpose": "std::env::current_dir", "category": "rust_runtime"},
    "std::env::current_exe": {"lib": "rust_std", "purpose": "std::env::current_exe", "category": "rust_runtime"},
    "std::env::home_dir": {"lib": "rust_std", "purpose": "std::env::home_dir", "category": "rust_runtime"},

    # --- std::panic (catch_unwind is central in malware defensive wrapping) ---
    "std::panic::catch_unwind": {"lib": "rust_std", "purpose": "std::panic::catch_unwind", "category": "rust_runtime"},
    "std::panic::resume_unwind": {"lib": "rust_std", "purpose": "std::panic::resume_unwind", "category": "rust_runtime"},
    "std::panic::set_hook": {"lib": "rust_std", "purpose": "std::panic::set_hook", "category": "rust_runtime"},
    "std::panic::take_hook": {"lib": "rust_std", "purpose": "std::panic::take_hook", "category": "rust_runtime"},

    # --- tokio async runtime (base) ---
    "tokio::runtime::Runtime::new": {"lib": "tokio", "purpose": "tokio::runtime::Runtime::new (multi-thread)", "category": "rust_async"},
    "tokio::runtime::Builder::new_current_thread": {"lib": "tokio", "purpose": "tokio single-thread runtime builder", "category": "rust_async"},
    "tokio::runtime::Builder::new_multi_thread": {"lib": "tokio", "purpose": "tokio multi-thread runtime builder", "category": "rust_async"},
    "tokio::runtime::Runtime::block_on": {"lib": "tokio", "purpose": "tokio::runtime::Runtime::block_on", "category": "rust_async"},
    "tokio::runtime::Runtime::spawn": {"lib": "tokio", "purpose": "tokio::runtime::Runtime::spawn", "category": "rust_async"},
    "tokio::task::spawn": {"lib": "tokio", "purpose": "tokio::task::spawn", "category": "rust_async"},
    "tokio::task::spawn_blocking": {"lib": "tokio", "purpose": "tokio::task::spawn_blocking", "category": "rust_async"},
    "tokio::task::JoinHandle::abort": {"lib": "tokio", "purpose": "tokio::task::JoinHandle::abort", "category": "rust_async"},
    "tokio::main": {"lib": "tokio", "purpose": "#[tokio::main] macro entry", "category": "rust_async"},
    "tokio::time::sleep": {"lib": "tokio", "purpose": "tokio::time::sleep", "category": "rust_async"},
    "tokio::time::timeout": {"lib": "tokio", "purpose": "tokio::time::timeout", "category": "rust_async"},
    "tokio::sync::Mutex::new": {"lib": "tokio", "purpose": "tokio::sync::Mutex::new (async)", "category": "rust_async"},
    "tokio::sync::RwLock::new": {"lib": "tokio", "purpose": "tokio::sync::RwLock::new (async)", "category": "rust_async"},
    "tokio::sync::mpsc::channel": {"lib": "tokio", "purpose": "tokio::sync::mpsc::channel (async)", "category": "rust_async"},
    "tokio::net::TcpListener::bind": {"lib": "tokio", "purpose": "tokio::net::TcpListener::bind", "category": "rust_async"},
    "tokio::net::TcpStream::connect": {"lib": "tokio", "purpose": "tokio::net::TcpStream::connect", "category": "rust_async"},
    "tokio::io::AsyncReadExt::read": {"lib": "tokio", "purpose": "tokio AsyncReadExt::read", "category": "rust_async"},
    "tokio::io::AsyncWriteExt::write": {"lib": "tokio", "purpose": "tokio AsyncWriteExt::write", "category": "rust_async"},

    # --- reqwest HTTP client (common C2 channel in malware) ---
    "reqwest::Client::new": {"lib": "reqwest", "purpose": "reqwest::Client::new (HTTP client)", "category": "rust_network"},
    "reqwest::Client::builder": {"lib": "reqwest", "purpose": "reqwest::Client builder (custom TLS/headers)", "category": "rust_network"},
    "reqwest::Client::get": {"lib": "reqwest", "purpose": "reqwest::Client::get", "category": "rust_network"},
    "reqwest::Client::post": {"lib": "reqwest", "purpose": "reqwest::Client::post", "category": "rust_network"},
    "reqwest::Client::put": {"lib": "reqwest", "purpose": "reqwest::Client::put", "category": "rust_network"},
    "reqwest::Client::delete": {"lib": "reqwest", "purpose": "reqwest::Client::delete", "category": "rust_network"},
    "reqwest::Client::head": {"lib": "reqwest", "purpose": "reqwest::Client::head", "category": "rust_network"},
    "reqwest::Client::request": {"lib": "reqwest", "purpose": "reqwest::Client::request (generic)", "category": "rust_network"},
    "reqwest::get": {"lib": "reqwest", "purpose": "reqwest::get (standalone GET)", "category": "rust_network"},
    "reqwest::Response::text": {"lib": "reqwest", "purpose": "reqwest::Response::text", "category": "rust_network"},
    "reqwest::Response::bytes": {"lib": "reqwest", "purpose": "reqwest::Response::bytes", "category": "rust_network"},
    "reqwest::Response::json": {"lib": "reqwest", "purpose": "reqwest::Response::json", "category": "rust_network"},
    "reqwest::RequestBuilder::send": {"lib": "reqwest", "purpose": "reqwest::RequestBuilder::send", "category": "rust_network"},
    "reqwest::RequestBuilder::header": {"lib": "reqwest", "purpose": "reqwest::RequestBuilder::header", "category": "rust_network"},
    "reqwest::RequestBuilder::body": {"lib": "reqwest", "purpose": "reqwest::RequestBuilder::body", "category": "rust_network"},
    "reqwest::RequestBuilder::json": {"lib": "reqwest", "purpose": "reqwest::RequestBuilder::json", "category": "rust_network"},

    # --- hyper (low-level HTTP, underlies reqwest) ---
    "hyper::Server::bind": {"lib": "hyper", "purpose": "hyper::Server::bind", "category": "rust_network"},
    "hyper::Client::new": {"lib": "hyper", "purpose": "hyper::Client::new", "category": "rust_network"},
    "hyper::Client::builder": {"lib": "hyper", "purpose": "hyper::Client::builder", "category": "rust_network"},
    "hyper::Body::from": {"lib": "hyper", "purpose": "hyper::Body::from", "category": "rust_network"},
    "hyper::Body::empty": {"lib": "hyper", "purpose": "hyper::Body::empty", "category": "rust_network"},
    "hyper::Request::builder": {"lib": "hyper", "purpose": "hyper::Request::builder", "category": "rust_network"},
    "hyper::Response::builder": {"lib": "hyper", "purpose": "hyper::Response::builder", "category": "rust_network"},
    "hyper::service::service_fn": {"lib": "hyper", "purpose": "hyper::service::service_fn", "category": "rust_network"},

    # --- serde (serialization backbone) ---
    "serde::ser::Serialize::serialize": {"lib": "serde", "purpose": "serde::ser::Serialize::serialize trait", "category": "rust_runtime"},
    "serde::de::Deserialize::deserialize": {"lib": "serde", "purpose": "serde::de::Deserialize::deserialize trait", "category": "rust_runtime"},
    "serde::de::DeserializeOwned::deserialize": {"lib": "serde", "purpose": "DeserializeOwned impl", "category": "rust_runtime"},
    "serde_json::from_str": {"lib": "serde_json", "purpose": "serde_json::from_str", "category": "rust_runtime"},
    "serde_json::from_slice": {"lib": "serde_json", "purpose": "serde_json::from_slice", "category": "rust_runtime"},
    "serde_json::to_string": {"lib": "serde_json", "purpose": "serde_json::to_string", "category": "rust_runtime"},
    "serde_json::to_vec": {"lib": "serde_json", "purpose": "serde_json::to_vec", "category": "rust_runtime"},
    "serde_json::Value::get": {"lib": "serde_json", "purpose": "serde_json::Value indexed get", "category": "rust_runtime"},

    # --- clap / structopt CLI parsers ---
    "clap::Parser::parse": {"lib": "clap", "purpose": "clap::Parser::parse (derive)", "category": "rust_runtime"},
    "clap::Parser::try_parse": {"lib": "clap", "purpose": "clap::Parser::try_parse", "category": "rust_runtime"},
    "clap::Parser::parse_from": {"lib": "clap", "purpose": "clap::Parser::parse_from (custom args)", "category": "rust_runtime"},
    "clap::Command::new": {"lib": "clap", "purpose": "clap::Command::new (builder)", "category": "rust_runtime"},
    "clap::Command::get_matches": {"lib": "clap", "purpose": "clap::Command::get_matches", "category": "rust_runtime"},
    "clap::Arg::new": {"lib": "clap", "purpose": "clap::Arg::new", "category": "rust_runtime"},
    "structopt::StructOpt::from_args": {"lib": "structopt", "purpose": "structopt::StructOpt::from_args", "category": "rust_runtime"},
    "structopt::StructOpt::from_iter": {"lib": "structopt", "purpose": "structopt::StructOpt::from_iter", "category": "rust_runtime"},

    # --- AES / AES-GCM (RustCrypto) ---
    "aes::Aes128::new": {"lib": "aes", "purpose": "aes::Aes128::new (block cipher)", "category": "rust_crypto"},
    "aes::Aes192::new": {"lib": "aes", "purpose": "aes::Aes192::new (block cipher)", "category": "rust_crypto"},
    "aes::Aes256::new": {"lib": "aes", "purpose": "aes::Aes256::new (block cipher)", "category": "rust_crypto"},
    "aes::Aes128::encrypt_block": {"lib": "aes", "purpose": "aes::Aes128 encrypt single block", "category": "rust_crypto"},
    "aes::Aes256::encrypt_block": {"lib": "aes", "purpose": "aes::Aes256 encrypt single block", "category": "rust_crypto"},
    "aes_gcm::Aes128Gcm::new": {"lib": "aes_gcm", "purpose": "aes_gcm::Aes128Gcm::new (AEAD)", "category": "rust_crypto"},
    "aes_gcm::Aes256Gcm::new": {"lib": "aes_gcm", "purpose": "aes_gcm::Aes256Gcm::new (AEAD)", "category": "rust_crypto"},
    "aes_gcm::Aes128Gcm::encrypt": {"lib": "aes_gcm", "purpose": "aes_gcm::Aes128Gcm::encrypt", "category": "rust_crypto"},
    "aes_gcm::Aes256Gcm::encrypt": {"lib": "aes_gcm", "purpose": "aes_gcm::Aes256Gcm::encrypt", "category": "rust_crypto"},
    "aes_gcm::Aes128Gcm::decrypt": {"lib": "aes_gcm", "purpose": "aes_gcm::Aes128Gcm::decrypt", "category": "rust_crypto"},
    "aes_gcm::Aes256Gcm::decrypt": {"lib": "aes_gcm", "purpose": "aes_gcm::Aes256Gcm::decrypt", "category": "rust_crypto"},

    # --- ChaCha20 / ChaCha20Poly1305 (RustCrypto) ---
    "chacha20::ChaCha20::new": {"lib": "chacha20", "purpose": "chacha20::ChaCha20::new (stream cipher)", "category": "rust_crypto"},
    "chacha20::ChaCha20::apply_keystream": {"lib": "chacha20", "purpose": "ChaCha20::apply_keystream", "category": "rust_crypto"},
    "chacha20poly1305::ChaCha20Poly1305::new": {"lib": "chacha20poly1305", "purpose": "ChaCha20Poly1305::new (AEAD)", "category": "rust_crypto"},
    "chacha20poly1305::ChaCha20Poly1305::encrypt": {"lib": "chacha20poly1305", "purpose": "ChaCha20Poly1305::encrypt", "category": "rust_crypto"},
    "chacha20poly1305::ChaCha20Poly1305::decrypt": {"lib": "chacha20poly1305", "purpose": "ChaCha20Poly1305::decrypt", "category": "rust_crypto"},
    "chacha20poly1305::XChaCha20Poly1305::new": {"lib": "chacha20poly1305", "purpose": "XChaCha20Poly1305::new (extended nonce)", "category": "rust_crypto"},
}


# ---------------------------------------------------------------------------
# Go runtime signatures
# ---------------------------------------------------------------------------
# Kapsama:
#   - Scheduler / goroutine core (main, goexit, morestack, gopark, newproc)
#   - Memory (mallocgc, makeslice, makemap, makechan)
#   - Map/channel fast-path variants (mapaccess1_fast64, chansend1, chanrecv1)
#   - GC (gcStart, gcBgMarkWorker, gcMarkDone, gcSweep)
#   - Panic/recover (gopanic, gorecover, throw)
#   - Print helpers (printstring, println)
#   - Type / interface conversion (convT2E, assertI2T, typehash)
#   - net / net/http (Dial, Listen, Get, NewRequest, Client.Do)
#   - crypto (crypto/aes, crypto/cipher, crypto/tls)
#   - encoding (json, base64)
#   - os (Open, Create, Exit, Getenv, Args)
#   - fmt (Printf, Sprintf, Println)
#   - goroutine closure naming (main.main.func1, pkg.(*T).Method)
# Platform-bagimsiz: Go binary her 3 platformda da gorulur.
# ---------------------------------------------------------------------------
_GO_RUNTIME_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- Scheduler / goroutine core ---
    "runtime.main": {"lib": "go_std", "purpose": "Go main entry (calls user main.main)", "category": "go_runtime"},
    "runtime.goexit": {"lib": "go_std", "purpose": "goroutine exit point", "category": "go_runtime"},
    "runtime.goexit0": {"lib": "go_std", "purpose": "goroutine exit (internal)", "category": "go_runtime"},
    "runtime.morestack": {"lib": "go_std", "purpose": "goroutine stack growth", "category": "go_runtime"},
    "runtime.morestack_noctxt": {"lib": "go_std", "purpose": "stack growth no closure context", "category": "go_runtime"},
    "runtime.gopark": {"lib": "go_std", "purpose": "park goroutine (block)", "category": "go_runtime"},
    "runtime.goready": {"lib": "go_std", "purpose": "mark goroutine runnable", "category": "go_runtime"},
    "runtime.gosched": {"lib": "go_std", "purpose": "yield goroutine", "category": "go_runtime"},
    "runtime.goroutineProfileWithLabels": {"lib": "go_std", "purpose": "goroutine profile snapshot", "category": "go_runtime"},
    "runtime.newproc": {"lib": "go_std", "purpose": "create new goroutine (go stmt)", "category": "go_runtime"},
    "runtime.newproc1": {"lib": "go_std", "purpose": "create new goroutine (internal)", "category": "go_runtime"},
    "runtime.gogo": {"lib": "go_std", "purpose": "switch to goroutine context", "category": "go_runtime"},
    "runtime.schedule": {"lib": "go_std", "purpose": "scheduler main loop", "category": "go_runtime"},
    "runtime.findrunnable": {"lib": "go_std", "purpose": "scheduler find runnable goroutine", "category": "go_runtime"},
    "runtime.execute": {"lib": "go_std", "purpose": "scheduler execute goroutine", "category": "go_runtime"},
    "runtime.park_m": {"lib": "go_std", "purpose": "park on m (machine thread)", "category": "go_runtime"},
    "runtime.ready": {"lib": "go_std", "purpose": "make goroutine ready to run", "category": "go_runtime"},
    "runtime.entersyscall": {"lib": "go_std", "purpose": "enter syscall state", "category": "go_runtime"},
    "runtime.exitsyscall": {"lib": "go_std", "purpose": "exit syscall state", "category": "go_runtime"},
    "runtime.mstart": {"lib": "go_std", "purpose": "start OS thread for Go", "category": "go_runtime"},
    "runtime.mstart0": {"lib": "go_std", "purpose": "OS thread start (initial)", "category": "go_runtime"},
    "runtime.rt0_go": {"lib": "go_std", "purpose": "Go bootstrap entry point", "category": "go_runtime"},
    "runtime.schedinit": {"lib": "go_std", "purpose": "scheduler initialization", "category": "go_runtime"},

    # --- Memory allocation ---
    "runtime.mallocgc": {"lib": "go_std", "purpose": "GC-aware heap allocator", "category": "go_runtime"},
    "runtime.newobject": {"lib": "go_std", "purpose": "allocate new object of type", "category": "go_runtime"},
    "runtime.newarray": {"lib": "go_std", "purpose": "allocate new array of type", "category": "go_runtime"},
    "runtime.makeslice": {"lib": "go_std", "purpose": "allocate slice header+backing", "category": "go_runtime"},
    "runtime.makeslice64": {"lib": "go_std", "purpose": "allocate slice (64-bit len)", "category": "go_runtime"},
    "runtime.makemap": {"lib": "go_std", "purpose": "allocate map (generic)", "category": "go_runtime"},
    "runtime.makemap_small": {"lib": "go_std", "purpose": "allocate small map (inline buckets)", "category": "go_runtime"},
    "runtime.makemap64": {"lib": "go_std", "purpose": "allocate map (64-bit cap)", "category": "go_runtime"},
    "runtime.makechan": {"lib": "go_std", "purpose": "allocate channel (generic)", "category": "go_runtime"},
    "runtime.makechan64": {"lib": "go_std", "purpose": "allocate channel (64-bit cap)", "category": "go_runtime"},
    "runtime.growslice": {"lib": "go_std", "purpose": "append helper grow slice", "category": "go_runtime"},
    "runtime.memmove": {"lib": "go_std", "purpose": "runtime memmove (bulk copy)", "category": "go_runtime"},
    "runtime.memclrNoHeapPointers": {"lib": "go_std", "purpose": "zero region without heap pointers", "category": "go_runtime"},
    "runtime.memclrHasPointers": {"lib": "go_std", "purpose": "zero region with heap pointers", "category": "go_runtime"},
    "runtime.typedmemmove": {"lib": "go_std", "purpose": "typed memmove (GC-aware)", "category": "go_runtime"},
    "runtime.typedslicecopy": {"lib": "go_std", "purpose": "typed slice copy (GC-aware)", "category": "go_runtime"},

    # --- Map fast-path variants ---
    "runtime.mapaccess1": {"lib": "go_std", "purpose": "map[k] read (returns *V)", "category": "go_runtime"},
    "runtime.mapaccess2": {"lib": "go_std", "purpose": "map[k] read with ok (v,ok = m[k])", "category": "go_runtime"},
    "runtime.mapaccess1_fast32": {"lib": "go_std", "purpose": "map[k] fast path uint32 key", "category": "go_runtime"},
    "runtime.mapaccess1_fast64": {"lib": "go_std", "purpose": "map[k] fast path uint64 key", "category": "go_runtime"},
    "runtime.mapaccess1_faststr": {"lib": "go_std", "purpose": "map[k] fast path string key", "category": "go_runtime"},
    "runtime.mapaccess2_fast32": {"lib": "go_std", "purpose": "map[k] ok fast path uint32", "category": "go_runtime"},
    "runtime.mapaccess2_fast64": {"lib": "go_std", "purpose": "map[k] ok fast path uint64", "category": "go_runtime"},
    "runtime.mapaccess2_faststr": {"lib": "go_std", "purpose": "map[k] ok fast path string", "category": "go_runtime"},
    "runtime.mapassign": {"lib": "go_std", "purpose": "map[k] = v assignment", "category": "go_runtime"},
    "runtime.mapassign_fast32": {"lib": "go_std", "purpose": "map assign fast path uint32", "category": "go_runtime"},
    "runtime.mapassign_fast64": {"lib": "go_std", "purpose": "map assign fast path uint64", "category": "go_runtime"},
    "runtime.mapassign_faststr": {"lib": "go_std", "purpose": "map assign fast path string", "category": "go_runtime"},
    "runtime.mapdelete": {"lib": "go_std", "purpose": "delete(m, k)", "category": "go_runtime"},
    "runtime.mapdelete_fast32": {"lib": "go_std", "purpose": "mapdelete fast path uint32", "category": "go_runtime"},
    "runtime.mapdelete_fast64": {"lib": "go_std", "purpose": "mapdelete fast path uint64", "category": "go_runtime"},
    "runtime.mapdelete_faststr": {"lib": "go_std", "purpose": "mapdelete fast path string", "category": "go_runtime"},
    "runtime.mapiterinit": {"lib": "go_std", "purpose": "map range init", "category": "go_runtime"},
    "runtime.mapiternext": {"lib": "go_std", "purpose": "map range next", "category": "go_runtime"},
    "runtime.mapclear": {"lib": "go_std", "purpose": "clear(map)", "category": "go_runtime"},

    # --- Channel ops ---
    "runtime.chansend": {"lib": "go_std", "purpose": "generic channel send", "category": "go_runtime"},
    "runtime.chansend1": {"lib": "go_std", "purpose": "ch <- v (blocking send)", "category": "go_runtime"},
    "runtime.chanrecv": {"lib": "go_std", "purpose": "generic channel receive", "category": "go_runtime"},
    "runtime.chanrecv1": {"lib": "go_std", "purpose": "v := <-ch (blocking recv)", "category": "go_runtime"},
    "runtime.chanrecv2": {"lib": "go_std", "purpose": "v, ok := <-ch", "category": "go_runtime"},
    "runtime.closechan": {"lib": "go_std", "purpose": "close(ch)", "category": "go_runtime"},
    "runtime.selectgo": {"lib": "go_std", "purpose": "select statement core", "category": "go_runtime"},
    "runtime.selectnbsend": {"lib": "go_std", "purpose": "non-blocking send (select default)", "category": "go_runtime"},
    "runtime.selectnbrecv": {"lib": "go_std", "purpose": "non-blocking recv (select default)", "category": "go_runtime"},

    # --- GC (garbage collector) ---
    "runtime.gcStart": {"lib": "go_std", "purpose": "begin GC cycle", "category": "go_runtime"},
    "runtime.gcMarkDone": {"lib": "go_std", "purpose": "GC mark phase complete", "category": "go_runtime"},
    "runtime.gcDrain": {"lib": "go_std", "purpose": "drain GC mark work queue", "category": "go_runtime"},
    "runtime.gcBgMarkWorker": {"lib": "go_std", "purpose": "background GC mark worker", "category": "go_runtime"},
    "runtime.gcSweep": {"lib": "go_std", "purpose": "GC sweep phase", "category": "go_runtime"},
    "runtime.gcenable": {"lib": "go_std", "purpose": "enable concurrent GC", "category": "go_runtime"},
    "runtime.GC": {"lib": "go_std", "purpose": "runtime.GC() force collection", "category": "go_runtime"},
    "runtime.SetFinalizer": {"lib": "go_std", "purpose": "runtime.SetFinalizer", "category": "go_runtime"},
    "runtime.KeepAlive": {"lib": "go_std", "purpose": "runtime.KeepAlive (prevent early GC)", "category": "go_runtime"},

    # --- Panic / recover / throw ---
    "runtime.panic": {"lib": "go_std", "purpose": "runtime.panic alias", "category": "go_runtime"},
    "runtime.gopanic": {"lib": "go_std", "purpose": "panic() runtime entry", "category": "go_runtime"},
    "runtime.gorecover": {"lib": "go_std", "purpose": "recover() runtime entry", "category": "go_runtime"},
    "runtime.throw": {"lib": "go_std", "purpose": "runtime fatal error (unrecoverable)", "category": "go_runtime"},
    "runtime.panicmem": {"lib": "go_std", "purpose": "memory access panic (nil deref)", "category": "go_runtime"},
    "runtime.panicdivide": {"lib": "go_std", "purpose": "integer division by zero panic", "category": "go_runtime"},
    "runtime.panicoverflow": {"lib": "go_std", "purpose": "integer overflow panic", "category": "go_runtime"},
    "runtime.panicindex": {"lib": "go_std", "purpose": "out-of-range index panic", "category": "go_runtime"},
    "runtime.panicslice": {"lib": "go_std", "purpose": "slice bounds panic", "category": "go_runtime"},

    # --- Print helpers (used by runtime.throw) ---
    "runtime.printstring": {"lib": "go_std", "purpose": "runtime print string", "category": "go_runtime"},
    "runtime.println": {"lib": "go_std", "purpose": "runtime print newline", "category": "go_runtime"},
    "runtime.printint": {"lib": "go_std", "purpose": "runtime print int", "category": "go_runtime"},
    "runtime.printfloat": {"lib": "go_std", "purpose": "runtime print float", "category": "go_runtime"},
    "runtime.printhex": {"lib": "go_std", "purpose": "runtime print hex", "category": "go_runtime"},
    "runtime.printpointer": {"lib": "go_std", "purpose": "runtime print pointer", "category": "go_runtime"},

    # --- Type / interface conversion ---
    "runtime.convT2E": {"lib": "go_std", "purpose": "concrete type to interface{} (v2)", "category": "go_runtime"},
    "runtime.convT2I": {"lib": "go_std", "purpose": "concrete type to interface (v2)", "category": "go_runtime"},
    "runtime.convT16": {"lib": "go_std", "purpose": "convert 16-byte value to interface", "category": "go_runtime"},
    "runtime.convT32": {"lib": "go_std", "purpose": "convert 32-byte value to interface", "category": "go_runtime"},
    "runtime.convT64": {"lib": "go_std", "purpose": "convert 64-byte value to interface", "category": "go_runtime"},
    "runtime.convTstring": {"lib": "go_std", "purpose": "convert string to interface", "category": "go_runtime"},
    "runtime.convTslice": {"lib": "go_std", "purpose": "convert slice to interface", "category": "go_runtime"},
    "runtime.convTnoptr": {"lib": "go_std", "purpose": "convert non-pointer value to interface", "category": "go_runtime"},
    "runtime.assertI2T": {"lib": "go_std", "purpose": "interface to concrete type assert", "category": "go_runtime"},
    "runtime.assertI2I": {"lib": "go_std", "purpose": "interface to interface assert", "category": "go_runtime"},
    "runtime.assertE2I": {"lib": "go_std", "purpose": "empty interface to interface assert", "category": "go_runtime"},
    "runtime.typehash": {"lib": "go_std", "purpose": "type-specific hash function", "category": "go_runtime"},
    "runtime.typesEqual": {"lib": "go_std", "purpose": "reflect type equality check", "category": "go_runtime"},
    "runtime.ifaceeq": {"lib": "go_std", "purpose": "interface value equality", "category": "go_runtime"},
    "runtime.efaceeq": {"lib": "go_std", "purpose": "empty interface equality", "category": "go_runtime"},

    # --- Locks / atomics (runtime-level) ---
    "runtime.lock": {"lib": "go_std", "purpose": "runtime internal lock acquire", "category": "go_runtime"},
    "runtime.unlock": {"lib": "go_std", "purpose": "runtime internal lock release", "category": "go_runtime"},
    "runtime.semacquire": {"lib": "go_std", "purpose": "semaphore acquire (sync pkg backend)", "category": "go_runtime"},
    "runtime.semrelease": {"lib": "go_std", "purpose": "semaphore release", "category": "go_runtime"},
    "runtime.atomicstore": {"lib": "go_std", "purpose": "atomic store", "category": "go_runtime"},
    "runtime.atomicload": {"lib": "go_std", "purpose": "atomic load", "category": "go_runtime"},

    # --- net (net package) ---
    "net.Dial": {"lib": "net", "purpose": "net.Dial (TCP/UDP/Unix connect)", "category": "go_network"},
    "net.DialTimeout": {"lib": "net", "purpose": "net.DialTimeout", "category": "go_network"},
    "net.DialTCP": {"lib": "net", "purpose": "net.DialTCP", "category": "go_network"},
    "net.DialUDP": {"lib": "net", "purpose": "net.DialUDP", "category": "go_network"},
    "net.Listen": {"lib": "net", "purpose": "net.Listen (TCP/UDP/Unix bind)", "category": "go_network"},
    "net.ListenTCP": {"lib": "net", "purpose": "net.ListenTCP", "category": "go_network"},
    "net.ListenUDP": {"lib": "net", "purpose": "net.ListenUDP", "category": "go_network"},
    "net.ListenPacket": {"lib": "net", "purpose": "net.ListenPacket (UDP)", "category": "go_network"},
    "net.LookupHost": {"lib": "net", "purpose": "DNS host lookup", "category": "go_network"},
    "net.LookupIP": {"lib": "net", "purpose": "DNS IP lookup", "category": "go_network"},
    "net.ResolveTCPAddr": {"lib": "net", "purpose": "resolve TCP address", "category": "go_network"},
    "net.(*TCPConn).Read": {"lib": "net", "purpose": "TCP connection Read", "category": "go_network"},
    "net.(*TCPConn).Write": {"lib": "net", "purpose": "TCP connection Write", "category": "go_network"},
    "net.(*TCPConn).Close": {"lib": "net", "purpose": "TCP connection Close", "category": "go_network"},
    "net.(*TCPListener).Accept": {"lib": "net", "purpose": "TCP listener Accept", "category": "go_network"},
    "net.(*UDPConn).ReadFrom": {"lib": "net", "purpose": "UDP ReadFrom", "category": "go_network"},
    "net.(*UDPConn).WriteTo": {"lib": "net", "purpose": "UDP WriteTo", "category": "go_network"},

    # --- net/http (HTTP client/server, common malware C2) ---
    "net/http.Get": {"lib": "net/http", "purpose": "http.Get (shortcut)", "category": "go_network"},
    "net/http.Post": {"lib": "net/http", "purpose": "http.Post (shortcut)", "category": "go_network"},
    "net/http.PostForm": {"lib": "net/http", "purpose": "http.PostForm", "category": "go_network"},
    "net/http.Head": {"lib": "net/http", "purpose": "http.Head", "category": "go_network"},
    "net/http.NewRequest": {"lib": "net/http", "purpose": "http.NewRequest", "category": "go_network"},
    "net/http.NewRequestWithContext": {"lib": "net/http", "purpose": "http.NewRequestWithContext", "category": "go_network"},
    "net/http.(*Client).Do": {"lib": "net/http", "purpose": "http.Client.Do", "category": "go_network"},
    "net/http.(*Client).Get": {"lib": "net/http", "purpose": "http.Client.Get", "category": "go_network"},
    "net/http.(*Client).Post": {"lib": "net/http", "purpose": "http.Client.Post", "category": "go_network"},
    "net/http.ListenAndServe": {"lib": "net/http", "purpose": "http.ListenAndServe", "category": "go_network"},
    "net/http.ListenAndServeTLS": {"lib": "net/http", "purpose": "http.ListenAndServeTLS", "category": "go_network"},
    "net/http.Serve": {"lib": "net/http", "purpose": "http.Serve", "category": "go_network"},
    "net/http.(*Server).ListenAndServe": {"lib": "net/http", "purpose": "http.Server.ListenAndServe", "category": "go_network"},
    "net/http.(*Server).Serve": {"lib": "net/http", "purpose": "http.Server.Serve", "category": "go_network"},
    "net/http.HandleFunc": {"lib": "net/http", "purpose": "http.HandleFunc", "category": "go_network"},
    "net/http.Handle": {"lib": "net/http", "purpose": "http.Handle", "category": "go_network"},
    "net/http.NewServeMux": {"lib": "net/http", "purpose": "http.NewServeMux", "category": "go_network"},
    "net/http.(*Request).Write": {"lib": "net/http", "purpose": "http.Request.Write", "category": "go_network"},
    "net/http.ReadResponse": {"lib": "net/http", "purpose": "http.ReadResponse", "category": "go_network"},

    # --- crypto/aes, crypto/cipher, crypto/tls ---
    "crypto/aes.NewCipher": {"lib": "crypto/aes", "purpose": "crypto/aes.NewCipher", "category": "go_crypto"},
    "crypto/cipher.NewGCM": {"lib": "crypto/cipher", "purpose": "crypto/cipher.NewGCM (AEAD)", "category": "go_crypto"},
    "crypto/cipher.NewGCMWithNonceSize": {"lib": "crypto/cipher", "purpose": "NewGCMWithNonceSize", "category": "go_crypto"},
    "crypto/cipher.NewCBCEncrypter": {"lib": "crypto/cipher", "purpose": "CBC encrypter", "category": "go_crypto"},
    "crypto/cipher.NewCBCDecrypter": {"lib": "crypto/cipher", "purpose": "CBC decrypter", "category": "go_crypto"},
    "crypto/cipher.NewCTR": {"lib": "crypto/cipher", "purpose": "CTR stream cipher", "category": "go_crypto"},
    "crypto/cipher.NewCFBEncrypter": {"lib": "crypto/cipher", "purpose": "CFB encrypter", "category": "go_crypto"},
    "crypto/cipher.NewCFBDecrypter": {"lib": "crypto/cipher", "purpose": "CFB decrypter", "category": "go_crypto"},
    "crypto/cipher.NewOFB": {"lib": "crypto/cipher", "purpose": "OFB stream cipher", "category": "go_crypto"},
    "crypto/tls.Dial": {"lib": "crypto/tls", "purpose": "tls.Dial (client TLS handshake)", "category": "go_crypto"},
    "crypto/tls.DialWithDialer": {"lib": "crypto/tls", "purpose": "tls.DialWithDialer", "category": "go_crypto"},
    "crypto/tls.Listen": {"lib": "crypto/tls", "purpose": "tls.Listen (server TLS)", "category": "go_crypto"},
    "crypto/tls.NewListener": {"lib": "crypto/tls", "purpose": "tls.NewListener", "category": "go_crypto"},
    "crypto/tls.Client": {"lib": "crypto/tls", "purpose": "tls.Client (wrap connection)", "category": "go_crypto"},
    "crypto/tls.Server": {"lib": "crypto/tls", "purpose": "tls.Server (wrap connection)", "category": "go_crypto"},
    "crypto/tls.(*Conn).Read": {"lib": "crypto/tls", "purpose": "tls.Conn.Read", "category": "go_crypto"},
    "crypto/tls.(*Conn).Write": {"lib": "crypto/tls", "purpose": "tls.Conn.Write", "category": "go_crypto"},
    "crypto/tls.(*Conn).Handshake": {"lib": "crypto/tls", "purpose": "tls.Conn.Handshake", "category": "go_crypto"},
    "crypto/tls.(*Conn).Close": {"lib": "crypto/tls", "purpose": "tls.Conn.Close", "category": "go_crypto"},
    "crypto/sha256.New": {"lib": "crypto/sha256", "purpose": "sha256.New hasher", "category": "go_crypto"},
    "crypto/sha256.Sum256": {"lib": "crypto/sha256", "purpose": "sha256.Sum256", "category": "go_crypto"},
    "crypto/sha512.New": {"lib": "crypto/sha512", "purpose": "sha512.New hasher", "category": "go_crypto"},
    "crypto/md5.New": {"lib": "crypto/md5", "purpose": "md5.New hasher", "category": "go_crypto"},
    "crypto/hmac.New": {"lib": "crypto/hmac", "purpose": "hmac.New", "category": "go_crypto"},
    "crypto/rand.Read": {"lib": "crypto/rand", "purpose": "crypto/rand.Read (CSPRNG)", "category": "go_crypto"},
    "crypto/rand.Int": {"lib": "crypto/rand", "purpose": "crypto/rand.Int", "category": "go_crypto"},

    # --- encoding (json, base64, hex) ---
    "encoding/json.Marshal": {"lib": "encoding/json", "purpose": "json.Marshal", "category": "go_io"},
    "encoding/json.MarshalIndent": {"lib": "encoding/json", "purpose": "json.MarshalIndent", "category": "go_io"},
    "encoding/json.Unmarshal": {"lib": "encoding/json", "purpose": "json.Unmarshal", "category": "go_io"},
    "encoding/json.NewEncoder": {"lib": "encoding/json", "purpose": "json.NewEncoder", "category": "go_io"},
    "encoding/json.NewDecoder": {"lib": "encoding/json", "purpose": "json.NewDecoder", "category": "go_io"},
    "encoding/json.(*Encoder).Encode": {"lib": "encoding/json", "purpose": "json.Encoder.Encode", "category": "go_io"},
    "encoding/json.(*Decoder).Decode": {"lib": "encoding/json", "purpose": "json.Decoder.Decode", "category": "go_io"},
    "encoding/base64.StdEncoding.EncodeToString": {"lib": "encoding/base64", "purpose": "base64 std encode", "category": "go_io"},
    "encoding/base64.StdEncoding.DecodeString": {"lib": "encoding/base64", "purpose": "base64 std decode", "category": "go_io"},
    "encoding/base64.URLEncoding.EncodeToString": {"lib": "encoding/base64", "purpose": "base64 URL encode", "category": "go_io"},
    "encoding/base64.URLEncoding.DecodeString": {"lib": "encoding/base64", "purpose": "base64 URL decode", "category": "go_io"},
    "encoding/base64.RawStdEncoding.EncodeToString": {"lib": "encoding/base64", "purpose": "base64 raw std encode", "category": "go_io"},
    "encoding/base64.RawStdEncoding.DecodeString": {"lib": "encoding/base64", "purpose": "base64 raw std decode", "category": "go_io"},
    "encoding/hex.EncodeToString": {"lib": "encoding/hex", "purpose": "hex.EncodeToString", "category": "go_io"},
    "encoding/hex.DecodeString": {"lib": "encoding/hex", "purpose": "hex.DecodeString", "category": "go_io"},
    "encoding/hex.Encode": {"lib": "encoding/hex", "purpose": "hex.Encode", "category": "go_io"},
    "encoding/hex.Decode": {"lib": "encoding/hex", "purpose": "hex.Decode", "category": "go_io"},

    # --- os package ---
    "os.Open": {"lib": "os", "purpose": "os.Open (read)", "category": "go_io"},
    "os.OpenFile": {"lib": "os", "purpose": "os.OpenFile", "category": "go_io"},
    "os.Create": {"lib": "os", "purpose": "os.Create", "category": "go_io"},
    "os.Remove": {"lib": "os", "purpose": "os.Remove", "category": "go_io"},
    "os.RemoveAll": {"lib": "os", "purpose": "os.RemoveAll", "category": "go_io"},
    "os.Rename": {"lib": "os", "purpose": "os.Rename", "category": "go_io"},
    "os.Mkdir": {"lib": "os", "purpose": "os.Mkdir", "category": "go_io"},
    "os.MkdirAll": {"lib": "os", "purpose": "os.MkdirAll", "category": "go_io"},
    "os.ReadFile": {"lib": "os", "purpose": "os.ReadFile (Go 1.16+)", "category": "go_io"},
    "os.WriteFile": {"lib": "os", "purpose": "os.WriteFile (Go 1.16+)", "category": "go_io"},
    "os.ReadDir": {"lib": "os", "purpose": "os.ReadDir", "category": "go_io"},
    "os.Exit": {"lib": "os", "purpose": "os.Exit", "category": "go_io"},
    "os.Getenv": {"lib": "os", "purpose": "os.Getenv", "category": "go_io"},
    "os.LookupEnv": {"lib": "os", "purpose": "os.LookupEnv", "category": "go_io"},
    "os.Setenv": {"lib": "os", "purpose": "os.Setenv", "category": "go_io"},
    "os.Unsetenv": {"lib": "os", "purpose": "os.Unsetenv", "category": "go_io"},
    "os.Args": {"lib": "os", "purpose": "os.Args global", "category": "go_io"},
    "os.Executable": {"lib": "os", "purpose": "os.Executable", "category": "go_io"},
    "os.Hostname": {"lib": "os", "purpose": "os.Hostname", "category": "go_io"},
    "os.Getwd": {"lib": "os", "purpose": "os.Getwd", "category": "go_io"},
    "os.Chdir": {"lib": "os", "purpose": "os.Chdir", "category": "go_io"},
    "os.Getpid": {"lib": "os", "purpose": "os.Getpid", "category": "go_io"},
    "os.Getppid": {"lib": "os", "purpose": "os.Getppid", "category": "go_io"},
    "os.UserHomeDir": {"lib": "os", "purpose": "os.UserHomeDir", "category": "go_io"},
    "os.TempDir": {"lib": "os", "purpose": "os.TempDir", "category": "go_io"},
    "os.(*File).Read": {"lib": "os", "purpose": "os.File.Read", "category": "go_io"},
    "os.(*File).Write": {"lib": "os", "purpose": "os.File.Write", "category": "go_io"},
    "os.(*File).Close": {"lib": "os", "purpose": "os.File.Close", "category": "go_io"},
    "os.(*File).Seek": {"lib": "os", "purpose": "os.File.Seek", "category": "go_io"},
    "os.(*File).Stat": {"lib": "os", "purpose": "os.File.Stat", "category": "go_io"},

    # --- fmt package ---
    "fmt.Printf": {"lib": "fmt", "purpose": "fmt.Printf", "category": "go_io"},
    "fmt.Println": {"lib": "fmt", "purpose": "fmt.Println", "category": "go_io"},
    "fmt.Print": {"lib": "fmt", "purpose": "fmt.Print", "category": "go_io"},
    "fmt.Sprintf": {"lib": "fmt", "purpose": "fmt.Sprintf", "category": "go_io"},
    "fmt.Sprintln": {"lib": "fmt", "purpose": "fmt.Sprintln", "category": "go_io"},
    "fmt.Sprint": {"lib": "fmt", "purpose": "fmt.Sprint", "category": "go_io"},
    "fmt.Fprintf": {"lib": "fmt", "purpose": "fmt.Fprintf", "category": "go_io"},
    "fmt.Fprintln": {"lib": "fmt", "purpose": "fmt.Fprintln", "category": "go_io"},
    "fmt.Fprint": {"lib": "fmt", "purpose": "fmt.Fprint", "category": "go_io"},
    "fmt.Errorf": {"lib": "fmt", "purpose": "fmt.Errorf (error wrap)", "category": "go_io"},
    "fmt.Scan": {"lib": "fmt", "purpose": "fmt.Scan", "category": "go_io"},
    "fmt.Scanf": {"lib": "fmt", "purpose": "fmt.Scanf", "category": "go_io"},
    "fmt.Scanln": {"lib": "fmt", "purpose": "fmt.Scanln", "category": "go_io"},
    "fmt.Sscan": {"lib": "fmt", "purpose": "fmt.Sscan", "category": "go_io"},
    "fmt.Sscanf": {"lib": "fmt", "purpose": "fmt.Sscanf", "category": "go_io"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook
# ---------------------------------------------------------------------------
# `signature_db.py` icindeki Faz 7 override block'u bu SIGNATURES dict'ini
# dogrudan import eder. Anahtar isimleri override tarafinda aranir:
#   "rust_runtime_signatures" -> _MODERN_RUST_RUNTIME_SIGNATURES
#   "go_runtime_signatures"   -> _MODERN_GO_RUNTIME_SIGNATURES
# Yeni dict'lerdir (legacy karsiligi yok). `_load_builtin_signatures` tuple'i
# bu sembollere Faz 7 override block'unda ref alir.
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "rust_runtime_signatures": _RUST_RUNTIME_SIGNATURES_DATA,
    "go_runtime_signatures": _GO_RUNTIME_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
