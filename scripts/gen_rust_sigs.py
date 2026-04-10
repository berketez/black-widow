#!/usr/bin/env python3
"""
Karadul Rust Signature Generator
=================================
Rust stdlib + popular crate fonksiyon sembollerini cikarir.

3 kaynak kullanir:
1. Homebrew'daki Rust binary'lerden (rg, etc.) nm ile gercek sembol cikartma
2. Rust v0 mangling pattern'lerinden kapsamli stdlib/crate signature uretimi
3. Rust legacy mangling (_ZN) pattern'lerinden uretim

Cikti: sigs/rust_expanded.json
"""

import json
import os
import re
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime


# ============================================================================
# BOLUM 1: Rust Legacy Mangling Demangle Edici
# ============================================================================

# Rust legacy mangling substitution'lari
RUST_LEGACY_SUBS = {
    "$LT$": "<",
    "$GT$": ">",
    "$RF$": "&",
    "$LP$": "(",
    "$RP$": ")",
    "$BP$": "*",
    "$C$": ",",
    "$SP$": "@",
    "$u20$": " ",
    "$u22$": '"',
    "$u27$": "'",
    "$u2b$": "+",
    "$u3b$": ";",
    "$u5b$": "[",
    "$u5d$": "]",
    "$u7b$": "{",
    "$u7d$": "}",
    "$u7e$": "~",
}


def demangle_rust_legacy(mangled: str) -> str | None:
    """
    Rust legacy mangling (_ZN...) formatini demangle eder.

    Format: _ZN<len1><name1><len2><name2>...17h<hash>E
    Ornek: _ZN4core3ptr13drop_in_place17h1234567890abcdefE
           -> core::ptr::drop_in_place

    Impl format: _ZN<toplam_len>_$LT$Type..as..Trait$GT$<method_len><method>17h<hash>E
    Ornek: _ZN100_$LT$anyhow..context..Quoted...as core..fmt..Write$GT$9write_str17h...E
           -> <anyhow::context::Quoted as core::fmt::Write>::write_str
    """
    # Leading underscore'u kaldir (macOS adds extra _)
    s = mangled
    if s.startswith("__ZN"):
        s = s[1:]  # Remove extra leading underscore
    if s.startswith("_ZN"):
        s = s[3:]
    elif s.startswith("_$"):
        # _$LT$... formati - impl bloklari
        s = s[1:]
    else:
        return None

    # Sondaki hash'i kaldir: 17h<16hex>E
    s = re.sub(r"17h[0-9a-f]{16}E$", "", s)
    # Sondaki E'yi kaldir (sadece E ile bitiyorsa)
    if s.endswith("E") and not s.endswith("EE"):
        s = s[:-1]

    # $ substitution'larini uygula
    for pat, repl in RUST_LEGACY_SUBS.items():
        s = s.replace(pat, repl)

    # ".." yerine "::" koy
    s = s.replace("..", "::")

    # Impl blogu mu? _<Type as Trait> formatinda olabilir
    # Bu durumda leading sayi + _<...> seklindedir
    impl_match = re.match(r"^(\d+)(_?<.+>)(.*)", s)
    if impl_match:
        _total_len = impl_match.group(1)
        impl_block = impl_match.group(2)
        rest = impl_match.group(3)

        # rest kisminda method ismi varsa cikar: <len><name> pattern
        methods = []
        i = 0
        while i < len(rest):
            num_str = ""
            while i < len(rest) and rest[i].isdigit():
                num_str += rest[i]
                i += 1
            if num_str:
                length = int(num_str)
                if i + length <= len(rest):
                    methods.append(rest[i : i + length])
                    i += length
                else:
                    if rest[i:]:
                        methods.append(rest[i:])
                    break
            else:
                if rest[i:]:
                    methods.append(rest[i:])
                break

        result = impl_block
        if methods:
            result += "::" + "::".join(methods)

        # Cleanup
        result = re.sub(r"::+", "::", result)
        result = result.strip(":")
        return result if result else None

    # Normal path: sayi-isim ciftlerini parse et
    parts = []
    i = 0
    while i < len(s):
        num_str = ""
        while i < len(s) and s[i].isdigit():
            num_str += s[i]
            i += 1
        if num_str:
            length = int(num_str)
            if i + length <= len(s):
                parts.append(s[i : i + length])
                i += length
            else:
                # Kalan her seyi al
                parts.append(s[i:])
                break
        else:
            # Sayi yok - kalan her seyi al
            if s[i:]:
                parts.append(s[i:])
            break

    if not parts:
        return None

    result = "::".join(parts)

    # Cleanup
    result = re.sub(r"::+", "::", result)
    result = result.strip(":")

    return result if result else None


def extract_crate_from_demangled(demangled: str) -> str:
    """Demangled isimden crate adini cikar."""
    # <Type as Trait> formati: "<foo::bar::Baz as quux::Trait>::method"
    # _<&foo::bar::Baz as quux::Trait>::method
    # _<&mut foo::bar::Baz as quux::Trait>::method
    # _<&[foo::bar::Baz] as quux::Trait>::method
    m = re.match(r"_?<(.+?)\s+as\s+.+?>", demangled)
    if m:
        inner = m.group(1)
        # Reference ve slice prefixlerini temizle
        inner = re.sub(r"^&\s*mut\s+", "", inner)
        inner = re.sub(r"^&\s*", "", inner)
        inner = inner.lstrip("[")

        crate = inner.split("::")[0]
        # Kalan special chars temizle
        crate = re.sub(r"[<>\[\]&*\s]", "", crate)
        if crate:
            return crate

    # Normal path: crate::mod::func
    parts = demangled.split("::")
    if parts:
        crate = parts[0]
        # Reference, slice, pointer ve diger prefixleri temizle
        crate = re.sub(r"^[_<>&*\[\]\s(]+", "", crate)
        crate = re.sub(r"^mut\s+", "", crate)
        crate = crate.strip()
        if crate:
            return crate
    return "unknown"


def categorize_rust_symbol(demangled: str, crate: str) -> str:
    """Rust sembolunu kategorize et."""
    d = demangled.lower()

    # Crate-based categories
    crate_cats = {
        "core": "rust_core",
        "alloc": "rust_alloc",
        "std": "rust_std",
        "tokio": "rust_async",
        "async_std": "rust_async",
        "futures": "rust_future",
        "serde": "rust_serde",
        "serde_json": "rust_serde",
        "serde_derive": "rust_serde",
        "regex": "rust_regex",
        "regex_automata": "rust_regex",
        "regex_syntax": "rust_regex",
        "hyper": "rust_http",
        "reqwest": "rust_http",
        "actix": "rust_web",
        "axum": "rust_web",
        "warp": "rust_web",
        "rocket": "rust_web",
        "clap": "rust_cli",
        "structopt": "rust_cli",
        "log": "rust_log",
        "tracing": "rust_tracing",
        "env_logger": "rust_log",
        "chrono": "rust_chrono",
        "time": "rust_time",
        "rand": "rust_rand",
        "rayon": "rust_parallel",
        "crossbeam": "rust_parallel",
        "parking_lot": "rust_sync",
        "bytes": "rust_bytes",
        "memchr": "rust_string",
        "aho_corasick": "rust_string",
        "hashbrown": "rust_collections",
        "indexmap": "rust_collections",
        "walkdir": "rust_fs",
        "globset": "rust_fs",
        "ignore": "rust_fs",
        "encoding_rs": "rust_encoding",
        "encoding_rs_io": "rust_encoding",
        "anyhow": "rust_error",
        "thiserror": "rust_error",
        "bstr": "rust_string",
        "termcolor": "rust_cli",
        "textwrap": "rust_cli",
        "pcre2": "rust_regex",
        "gimli": "rust_debug",
        "object": "rust_binary",
        "rustc_demangle": "rust_debug",
        "ryu": "rust_num",
        "num": "rust_num",
        "num_traits": "rust_num",
        "libc": "rust_ffi",
        "winapi": "rust_ffi",
        "nix": "rust_unix",
        "mio": "rust_async_io",
        "diesel": "rust_db",
        "sqlx": "rust_db",
        "rusqlite": "rust_db",
        "tonic": "rust_grpc",
        "prost": "rust_protobuf",
    }

    if crate in crate_cats:
        return crate_cats[crate]

    # Keyword-based fallback
    if "option" in d:
        return "rust_option"
    if "result" in d:
        return "rust_result"
    if "vec" in d and ("push" in d or "pop" in d or "insert" in d):
        return "rust_vec"
    if "hashmap" in d or "hash_map" in d:
        return "rust_collections"
    if "string" in d:
        return "rust_string"
    if "io::" in d or "read" in d or "write" in d:
        return "rust_io"
    if "fmt" in d:
        return "rust_fmt"
    if "iter" in d:
        return "rust_iter"
    if "sync" in d or "mutex" in d or "rwlock" in d:
        return "rust_sync"
    if "thread" in d:
        return "rust_thread"
    if "alloc" in d or "dealloc" in d or "heap" in d:
        return "rust_alloc"
    if "drop" in d:
        return "rust_drop"
    if "clone" in d:
        return "rust_clone"
    if "panic" in d or "unwind" in d:
        return "rust_panic"
    if "net" in d or "tcp" in d or "udp" in d:
        return "rust_net"
    if "fs::" in d or "path" in d or "file" in d:
        return "rust_fs"

    return f"rust_{crate}" if crate != "unknown" else "rust_misc"


# ============================================================================
# BOLUM 2: Binary'den Sembol Cikartma
# ============================================================================

def is_rust_legacy_symbol(sym_name: str) -> bool:
    """
    Bir _ZN sembolunun gercekten Rust oldugunu dogrula.
    Rust legacy mangling: _ZN...<hash_len>h<16_hex>E seklinde biter.
    C++ _ZN sembolleri bu pattern'e uymaz.
    """
    # Rust sembolleri 17h<16hex>E ile biter
    if re.search(r"17h[0-9a-f]{16}E$", sym_name):
        return True
    # Veya $LT$, $GT$ gibi Rust-specific escape'ler iceriyorsa
    if "$LT$" in sym_name or "$GT$" in sym_name or "$RF$" in sym_name:
        return True
    # Veya bilinen Rust crate isimlerini iceriyorsa
    rust_crate_patterns = [
        "core..", "alloc..", "std..", "serde", "tokio", "regex",
        "encoding_rs", "aho_corasick", "memchr", "anyhow",
        "hashbrown", "crossbeam", "walkdir", "globset", "ignore",
        "bstr", "termcolor", "rustc_demangle", "grep_",
    ]
    for pat in rust_crate_patterns:
        if pat in sym_name:
            return True
    return False


def extract_symbols_from_binary(binary_path: str) -> list[tuple[str, str]]:
    """
    Binary'den Rust sembollerini cikar.
    Returns: [(mangled_symbol, symbol_type), ...]
    """
    try:
        result = subprocess.run(
            ["nm", "-gU", binary_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    symbols = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            sym_type = parts[1]
            sym_name = parts[2]
        elif len(parts) == 2:
            sym_type = parts[0]
            sym_name = parts[1]
        else:
            continue

        # Rust v0 mangling (_R prefix)
        if sym_name.startswith("__RNv") or sym_name.startswith("__RINv"):
            symbols.append((sym_name, sym_type))
        # Rust legacy mangling (_ZN) - sadece Rust oldugu dogrulanmis
        elif "__ZN" in sym_name and is_rust_legacy_symbol(sym_name):
            symbols.append((sym_name, sym_type))

    return symbols


def process_binary_symbols(binary_path: str, source_name: str) -> dict:
    """Binary'den Rust signature'larini cikar ve dict olarak don."""
    symbols = extract_symbols_from_binary(binary_path)
    sigs = {}

    for mangled, sym_type in symbols:
        # Legacy mangling
        if "__ZN" in mangled:
            demangled = demangle_rust_legacy(mangled)
            if demangled and len(demangled) > 3:
                crate = extract_crate_from_demangled(demangled)
                category = categorize_rust_symbol(demangled, crate)
                # Key olarak mangled sembol kullan
                sigs[mangled] = {
                    "lib": crate,
                    "purpose": demangled,
                    "category": category,
                    "source": source_name,
                }

        # v0 mangling
        elif mangled.startswith("__RNv") or mangled.startswith("__RINv"):
            # v0 mangling icin basit demangle
            sigs[mangled] = {
                "lib": "rust_runtime",
                "purpose": f"rust_v0_symbol({mangled})",
                "category": "rust_v0",
                "source": source_name,
            }

    return sigs


# ============================================================================
# BOLUM 3: Rust v0 Mangling Encoder
# ============================================================================

def rust_v0_encode_ident(name: str) -> str:
    """Rust v0 mangling icin identifier encode et."""
    # Basit isimler: <len><name>
    # Punycode gerekiyorsa: <len>u<punycode>
    # Biz sadece ASCII isimleri destekliyoruz
    return f"{len(name)}{name}"


def rust_v0_crate_hash(crate_name: str) -> str:
    """
    Fake ama tutarli bir crate hash uret.
    Gercek hash rustc'nin hesapladigi disambiguator.
    Biz pattern matching icin kullanacagiz.
    """
    import hashlib
    h = hashlib.md5(crate_name.encode()).hexdigest()[:16]
    # Base-62 gibi encode et (basit versiyon)
    return h[:12]


def mangle_rust_v0_path(crate: str, path_parts: list[str]) -> str:
    """
    Rust v0 mangling ile sembol adi olustur.

    Rust v0 format:
      _R                    - prefix
      Nv                    - value namespace item
      NtCs<hash>_<len><crate>  - crate root
      <len><name>           - path component

    Ornek: std::vec::Vec::push ->
      _RNvMs_NtCs<hash>_3std3vecINtB4_3VecpE4push

    Ama gercek v0 mangling cok karmasik (generics, closures, etc).
    Biz pattern matching icin yakin yaklasimlar uretiriz.
    """
    h = rust_v0_crate_hash(crate)

    # Crate root: Cs<hash>_<len><crate>
    crate_part = f"Cs{h}_{rust_v0_encode_ident(crate)}"

    # Path parts: Nt (type namespace) veya Nv (value namespace)
    # Son eleman value (fonksiyon), digerler type (module/type)
    if len(path_parts) == 0:
        return f"_RNv{crate_part}"

    result = crate_part
    for i, part in enumerate(path_parts[:-1]):
        result = f"Nt{result}{rust_v0_encode_ident(part)}"

    # Son part value namespace
    result = f"Nv{result}{rust_v0_encode_ident(path_parts[-1])}"

    return f"_R{result}"


def mangle_rust_legacy(crate: str, path_parts: list[str]) -> str:
    """
    Rust legacy mangling (_ZN...) ile sembol adi olustur.

    Format: _ZN<len1><name1><len2><name2>...17h<hash>E

    Ornek: std::vec::Vec::push ->
      _ZN3std3vec3Vec4push17h1234567890abcdefE
    """
    import hashlib
    parts = [crate] + path_parts
    encoded = "".join(f"{len(p)}{p}" for p in parts)
    # Fake hash
    h = hashlib.md5("::".join(parts).encode()).hexdigest()[:16]
    return f"_ZN{encoded}17h{h}E"


# ============================================================================
# BOLUM 4: Kapsamli Rust Stdlib + Crate Signature Veritabani
# ============================================================================

def generate_comprehensive_signatures() -> dict:
    """
    Rust stdlib ve popular crate'ler icin kapsamli signature DB uret.
    Hem v0 hem legacy mangling key'leri olusturur.
    """
    sigs = {}

    # Her signature icin:
    # 1. Demangled path (crate::mod::Type::func)
    # 2. Lib adi
    # 3. Purpose aciklamasi
    # 4. Category

    # Format: (crate, [path_parts], purpose, category)
    SIGNATURES = []

    # -------------------------------------------------------------------------
    # CORE CRATE (core::)
    # -------------------------------------------------------------------------

    # Option
    for method, purpose in [
        ("is_some", "check if Option contains a value"),
        ("is_none", "check if Option is None"),
        ("is_some_and", "check if Option contains value matching predicate"),
        ("unwrap", "extract value or panic"),
        ("unwrap_or", "extract value or return default"),
        ("unwrap_or_else", "extract value or compute default"),
        ("unwrap_or_default", "extract value or return Default"),
        ("unwrap_unchecked", "extract value without checking (unsafe)"),
        ("expect", "extract value or panic with message"),
        ("map", "transform contained value"),
        ("map_or", "transform or return default"),
        ("map_or_else", "transform or compute default"),
        ("and", "return None if None, otherwise other"),
        ("and_then", "flatmap on Option"),
        ("or", "return self if Some, otherwise other"),
        ("or_else", "return self if Some, otherwise compute"),
        ("filter", "return None if predicate fails"),
        ("zip", "combine two Options into tuple"),
        ("zip_with", "combine two Options with function"),
        ("take", "take value leaving None"),
        ("replace", "replace value returning old"),
        ("get_or_insert", "get value or insert default"),
        ("get_or_insert_with", "get value or insert computed"),
        ("as_ref", "convert &Option<T> to Option<&T>"),
        ("as_mut", "convert &mut Option<T> to Option<&mut T>"),
        ("as_deref", "convert Option<T> to Option<&T::Target>"),
        ("as_pin_ref", "convert Pin<&Option<T>> to Option<Pin<&T>>"),
        ("flatten", "flatten Option<Option<T>> to Option<T>"),
        ("ok_or", "transform Option into Result"),
        ("ok_or_else", "transform Option into Result lazily"),
        ("transpose", "transpose Option<Result> to Result<Option>"),
        ("cloned", "clone inner value"),
        ("copied", "copy inner value"),
        ("inspect", "inspect value without consuming"),
        ("iter", "get iterator over Option"),
    ]:
        SIGNATURES.append(("core", ["option", "Option", method], purpose, "rust_option"))

    # Result
    for method, purpose in [
        ("is_ok", "check if Result is Ok"),
        ("is_err", "check if Result is Err"),
        ("is_ok_and", "check if Ok and predicate matches"),
        ("is_err_and", "check if Err and predicate matches"),
        ("ok", "convert Result to Option discarding Err"),
        ("err", "convert Result to Option discarding Ok"),
        ("unwrap", "extract Ok value or panic"),
        ("unwrap_err", "extract Err value or panic"),
        ("unwrap_or", "extract Ok or return default"),
        ("unwrap_or_else", "extract Ok or compute default"),
        ("unwrap_or_default", "extract Ok or return Default"),
        ("expect", "extract Ok or panic with message"),
        ("expect_err", "extract Err or panic with message"),
        ("map", "transform Ok value"),
        ("map_err", "transform Err value"),
        ("map_or", "transform Ok or return default"),
        ("map_or_else", "transform Ok or compute from Err"),
        ("and", "return Err if Err, otherwise other"),
        ("and_then", "flatmap on Result"),
        ("or", "return self if Ok, otherwise other"),
        ("or_else", "return self if Ok, otherwise compute"),
        ("as_ref", "convert &Result to Result<&T, &E>"),
        ("as_mut", "convert &mut Result to Result<&mut T, &mut E>"),
        ("as_deref", "deref Result value"),
        ("transpose", "transpose Result<Option> to Option<Result>"),
        ("flatten", "flatten Result<Result> to Result"),
        ("inspect", "inspect Ok value without consuming"),
        ("inspect_err", "inspect Err value without consuming"),
        ("iter", "get iterator over Result Ok value"),
        ("cloned", "clone inner Ok value"),
        ("copied", "copy inner Ok value"),
    ]:
        SIGNATURES.append(("core", ["result", "Result", method], purpose, "rust_result"))

    # Iterator
    for method, purpose in [
        ("next", "advance iterator and return next value"),
        ("size_hint", "return bounds on remaining length"),
        ("count", "consume iterator counting elements"),
        ("last", "consume iterator returning last element"),
        ("nth", "return nth element"),
        ("step_by", "create stepping iterator"),
        ("chain", "chain two iterators"),
        ("zip", "zip two iterators"),
        ("unzip", "unzip iterator of pairs"),
        ("map", "transform elements"),
        ("for_each", "call closure on each element"),
        ("filter", "filter elements by predicate"),
        ("filter_map", "filter and transform elements"),
        ("enumerate", "add index to elements"),
        ("peekable", "create peekable iterator"),
        ("skip_while", "skip elements while predicate true"),
        ("take_while", "take elements while predicate true"),
        ("map_while", "map elements while Some"),
        ("skip", "skip first n elements"),
        ("take", "take first n elements"),
        ("scan", "stateful map"),
        ("flat_map", "map and flatten"),
        ("flatten", "flatten nested iterators"),
        ("fuse", "create fused iterator"),
        ("inspect", "inspect elements without consuming"),
        ("by_ref", "borrow iterator"),
        ("collect", "collect into collection"),
        ("partition", "partition into two collections"),
        ("fold", "fold elements with accumulator"),
        ("reduce", "reduce elements to single value"),
        ("try_fold", "fold with early return"),
        ("try_for_each", "for_each with early return"),
        ("all", "check if all elements match predicate"),
        ("any", "check if any element matches predicate"),
        ("find", "find first matching element"),
        ("find_map", "find and transform first match"),
        ("position", "find index of first match"),
        ("rposition", "find index of last match"),
        ("max", "find maximum element"),
        ("min", "find minimum element"),
        ("max_by", "find max by comparator"),
        ("min_by", "find min by comparator"),
        ("max_by_key", "find max by key function"),
        ("min_by_key", "find min by key function"),
        ("rev", "reverse iterator"),
        ("cloned", "clone referenced elements"),
        ("copied", "copy referenced elements"),
        ("cycle", "repeat iterator endlessly"),
        ("sum", "sum all elements"),
        ("product", "multiply all elements"),
        ("cmp", "lexicographic compare iterators"),
        ("partial_cmp", "partial lexicographic compare"),
        ("eq", "check iterator equality"),
        ("ne", "check iterator inequality"),
        ("lt", "check iterator less than"),
        ("le", "check iterator less or equal"),
        ("gt", "check iterator greater than"),
        ("ge", "check iterator greater or equal"),
        ("is_sorted", "check if iterator is sorted"),
        ("is_sorted_by", "check if sorted by comparator"),
        ("is_sorted_by_key", "check if sorted by key"),
    ]:
        SIGNATURES.append(("core", ["iter", "Iterator", method], purpose, "rust_iter"))

    # core::ptr
    for method, purpose in [
        ("drop_in_place", "drop value at pointer"),
        ("null", "create null pointer"),
        ("null_mut", "create null mutable pointer"),
        ("read", "read value from pointer"),
        ("read_unaligned", "read unaligned value from pointer"),
        ("read_volatile", "read volatile value from pointer"),
        ("write", "write value to pointer"),
        ("write_unaligned", "write unaligned value to pointer"),
        ("write_volatile", "write volatile value to pointer"),
        ("write_bytes", "fill memory with byte value"),
        ("copy", "copy memory regions (may overlap)"),
        ("copy_nonoverlapping", "copy non-overlapping memory regions"),
        ("swap", "swap values at two pointers"),
        ("swap_nonoverlapping", "swap non-overlapping memory regions"),
        ("replace", "replace value at pointer returning old"),
        ("addr_of", "create const pointer to value"),
        ("addr_of_mut", "create mutable pointer to value"),
        ("eq", "compare pointers for equality"),
        ("hash", "hash pointer address"),
        ("slice_from_raw_parts", "create slice from raw pointer"),
        ("slice_from_raw_parts_mut", "create mutable slice from raw pointer"),
    ]:
        SIGNATURES.append(("core", ["ptr", method], purpose, "rust_ptr"))

    # core::mem
    for method, purpose in [
        ("size_of", "return size of type in bytes"),
        ("size_of_val", "return size of value in bytes"),
        ("align_of", "return alignment of type"),
        ("align_of_val", "return alignment of value"),
        ("forget", "take ownership without running destructor"),
        ("drop", "explicitly drop value"),
        ("replace", "replace value returning old"),
        ("swap", "swap two values"),
        ("take", "take value replacing with default"),
        ("zeroed", "create zero-initialized value"),
        ("transmute", "reinterpret bits as different type"),
        ("transmute_copy", "transmute by copying bits"),
        ("needs_drop", "check if type needs drop"),
        ("discriminant", "get enum discriminant"),
        ("ManuallyDrop", "wrapper to prevent auto-drop"),
        ("MaybeUninit", "wrapper for possibly uninitialized data"),
        ("offset_of", "get byte offset of struct field"),
    ]:
        SIGNATURES.append(("core", ["mem", method], purpose, "rust_mem"))

    # core::fmt
    for method, purpose in [
        ("write", "write formatted data"),
        ("format", "create formatted String"),
        ("Debug", "debug formatting trait"),
        ("Display", "user-facing formatting trait"),
        ("Formatter", "formatting context"),
        ("Arguments", "pre-compiled format arguments"),
        ("write_str", "write string to formatter"),
        ("write_fmt", "write formatted args to formatter"),
        ("pad", "pad string to alignment"),
        ("pad_integral", "pad integral number"),
        ("debug_struct", "create debug struct formatter"),
        ("debug_tuple", "create debug tuple formatter"),
        ("debug_list", "create debug list formatter"),
        ("debug_set", "create debug set formatter"),
        ("debug_map", "create debug map formatter"),
    ]:
        SIGNATURES.append(("core", ["fmt", method], purpose, "rust_fmt"))

    # core::ops
    for (trait_name, method, purpose) in [
        ("Add", "add", "addition operator (+)"),
        ("Sub", "sub", "subtraction operator (-)"),
        ("Mul", "mul", "multiplication operator (*)"),
        ("Div", "div", "division operator (/)"),
        ("Rem", "rem", "remainder operator (%)"),
        ("Neg", "neg", "negation operator (-)"),
        ("Not", "not", "logical not operator (!)"),
        ("BitAnd", "bitand", "bitwise AND (&)"),
        ("BitOr", "bitor", "bitwise OR (|)"),
        ("BitXor", "bitxor", "bitwise XOR (^)"),
        ("Shl", "shl", "left shift (<<)"),
        ("Shr", "shr", "right shift (>>)"),
        ("Index", "index", "immutable indexing []"),
        ("IndexMut", "index_mut", "mutable indexing []"),
        ("Deref", "deref", "dereference operator *"),
        ("DerefMut", "deref_mut", "mutable dereference operator *"),
        ("Drop", "drop", "destructor"),
        ("Fn", "call", "callable (immutable borrow)"),
        ("FnMut", "call_mut", "callable (mutable borrow)"),
        ("FnOnce", "call_once", "callable (ownership)"),
        ("RangeFull", "new", "unbounded range (..)"),
        ("Range", "new", "half-open range (a..b)"),
        ("RangeFrom", "new", "range from (a..)"),
        ("RangeTo", "new", "range to (..b)"),
        ("RangeInclusive", "new", "inclusive range (a..=b)"),
    ]:
        SIGNATURES.append(("core", ["ops", trait_name, method], purpose, "rust_ops"))

    # core::cmp
    for method, purpose in [
        ("min", "return minimum of two values"),
        ("max", "return maximum of two values"),
        ("min_by", "return min by comparator"),
        ("max_by", "return max by comparator"),
        ("min_by_key", "return min by key function"),
        ("max_by_key", "return max by key function"),
        ("Ordering", "comparison result enum"),
        ("PartialEq", "partial equality trait"),
        ("Eq", "total equality trait"),
        ("PartialOrd", "partial ordering trait"),
        ("Ord", "total ordering trait"),
        ("Reverse", "reverse ordering wrapper"),
        ("clamp", "clamp value to range"),
    ]:
        SIGNATURES.append(("core", ["cmp", method], purpose, "rust_cmp"))

    # core::convert
    for method, purpose in [
        ("From", "value-to-value conversion"),
        ("Into", "value-to-value conversion (inverse From)"),
        ("TryFrom", "fallible value-to-value conversion"),
        ("TryInto", "fallible value-to-value conversion"),
        ("AsRef", "cheap reference-to-reference conversion"),
        ("AsMut", "cheap mutable reference conversion"),
        ("identity", "identity function"),
        ("Infallible", "type that can never happen"),
    ]:
        SIGNATURES.append(("core", ["convert", method], purpose, "rust_convert"))

    # core::clone / core::default / core::marker
    SIGNATURES.extend([
        ("core", ["clone", "Clone", "clone"], "create duplicate of value", "rust_clone"),
        ("core", ["clone", "Clone", "clone_from"], "clone from another value", "rust_clone"),
        ("core", ["default", "Default", "default"], "create default value", "rust_default"),
        ("core", ["marker", "Copy"], "bitwise copyable marker", "rust_marker"),
        ("core", ["marker", "Send"], "transferable across threads marker", "rust_marker"),
        ("core", ["marker", "Sync"], "shareable across threads marker", "rust_marker"),
        ("core", ["marker", "Sized"], "known size at compile time marker", "rust_marker"),
        ("core", ["marker", "Unpin"], "safe to move after pinning marker", "rust_marker"),
        ("core", ["marker", "PhantomData"], "zero-size phantom type marker", "rust_marker"),
    ])

    # core::hash
    for method, purpose in [
        ("hash", "feed value into Hasher"),
        ("hash_slice", "hash slice of values"),
        ("finish", "finish hashing and return result"),
        ("write", "write bytes to hasher"),
        ("write_u8", "write u8 to hasher"),
        ("write_u16", "write u16 to hasher"),
        ("write_u32", "write u32 to hasher"),
        ("write_u64", "write u64 to hasher"),
        ("write_u128", "write u128 to hasher"),
        ("write_usize", "write usize to hasher"),
        ("write_i8", "write i8 to hasher"),
        ("write_i16", "write i16 to hasher"),
        ("write_i32", "write i32 to hasher"),
        ("write_i64", "write i64 to hasher"),
    ]:
        SIGNATURES.append(("core", ["hash", "Hasher", method], purpose, "rust_hash"))

    # core::cell
    for method, purpose in [
        ("new", "create new Cell"),
        ("get", "get copy of contained value"),
        ("set", "set contained value"),
        ("replace", "replace contained value"),
        ("swap", "swap values of two Cells"),
        ("take", "take value leaving default"),
        ("into_inner", "unwrap contained value"),
    ]:
        SIGNATURES.append(("core", ["cell", "Cell", method], purpose, "rust_cell"))

    for method, purpose in [
        ("new", "create new RefCell"),
        ("borrow", "immutably borrow contained value"),
        ("borrow_mut", "mutably borrow contained value"),
        ("try_borrow", "try to immutably borrow"),
        ("try_borrow_mut", "try to mutably borrow"),
        ("replace", "replace contained value"),
        ("replace_with", "replace with computed value"),
        ("swap", "swap values of two RefCells"),
        ("into_inner", "unwrap contained value"),
    ]:
        SIGNATURES.append(("core", ["cell", "RefCell", method], purpose, "rust_cell"))

    # core::slice
    for method, purpose in [
        ("len", "return length of slice"),
        ("is_empty", "check if slice is empty"),
        ("first", "get first element"),
        ("last", "get last element"),
        ("get", "get element by index"),
        ("get_mut", "get mutable element by index"),
        ("get_unchecked", "get element without bounds check"),
        ("split_at", "split slice at index"),
        ("split_first", "split off first element"),
        ("split_last", "split off last element"),
        ("iter", "get immutable iterator"),
        ("iter_mut", "get mutable iterator"),
        ("windows", "get sliding windows iterator"),
        ("chunks", "get chunks iterator"),
        ("chunks_exact", "get exact chunks iterator"),
        ("rchunks", "get reverse chunks iterator"),
        ("split", "split by predicate"),
        ("splitn", "split into n parts"),
        ("contains", "check if slice contains value"),
        ("starts_with", "check prefix"),
        ("ends_with", "check suffix"),
        ("binary_search", "binary search for value"),
        ("binary_search_by", "binary search by comparator"),
        ("binary_search_by_key", "binary search by key"),
        ("sort", "sort elements (stable)"),
        ("sort_by", "sort by comparator"),
        ("sort_by_key", "sort by key function"),
        ("sort_unstable", "sort elements (unstable, faster)"),
        ("sort_unstable_by", "unstable sort by comparator"),
        ("reverse", "reverse elements in place"),
        ("rotate_left", "rotate elements left"),
        ("rotate_right", "rotate elements right"),
        ("fill", "fill slice with value"),
        ("fill_with", "fill slice with closure"),
        ("copy_from_slice", "copy from another slice"),
        ("clone_from_slice", "clone from another slice"),
        ("swap", "swap two elements"),
        ("swap_with_slice", "swap with another slice"),
        ("to_vec", "copy slice to Vec"),
        ("repeat", "repeat slice n times"),
        ("concat", "concatenate slices"),
        ("join", "join slices with separator"),
        ("flatten", "flatten slice of slices"),
        ("as_ptr", "get raw pointer to slice data"),
        ("as_mut_ptr", "get mutable raw pointer to slice data"),
    ]:
        SIGNATURES.append(("core", ["slice", method], purpose, "rust_slice"))

    # core::str
    for method, purpose in [
        ("len", "return byte length of string"),
        ("is_empty", "check if string is empty"),
        ("is_char_boundary", "check if index is char boundary"),
        ("as_bytes", "convert to byte slice"),
        ("as_ptr", "get raw pointer to string data"),
        ("chars", "get character iterator"),
        ("char_indices", "get char iterator with byte indices"),
        ("bytes", "get byte iterator"),
        ("lines", "get line iterator"),
        ("split_whitespace", "split by whitespace"),
        ("split_ascii_whitespace", "split by ASCII whitespace"),
        ("contains", "check if contains pattern"),
        ("starts_with", "check string prefix"),
        ("ends_with", "check string suffix"),
        ("find", "find first occurrence of pattern"),
        ("rfind", "find last occurrence of pattern"),
        ("split", "split by pattern"),
        ("splitn", "split into n parts"),
        ("rsplit", "reverse split by pattern"),
        ("rsplitn", "reverse split into n parts"),
        ("matches", "get pattern match iterator"),
        ("match_indices", "get pattern match index iterator"),
        ("trim", "trim whitespace from both ends"),
        ("trim_start", "trim whitespace from start"),
        ("trim_end", "trim whitespace from end"),
        ("trim_matches", "trim matching characters"),
        ("strip_prefix", "strip prefix returning Option"),
        ("strip_suffix", "strip suffix returning Option"),
        ("parse", "parse string into type"),
        ("to_lowercase", "convert to lowercase String"),
        ("to_uppercase", "convert to uppercase String"),
        ("to_ascii_lowercase", "convert to ASCII lowercase"),
        ("to_ascii_uppercase", "convert to ASCII uppercase"),
        ("repeat", "repeat string n times"),
        ("replace", "replace all occurrences"),
        ("replacen", "replace first n occurrences"),
        ("to_string", "convert to String"),
        ("eq_ignore_ascii_case", "case-insensitive ASCII comparison"),
        ("make_ascii_lowercase", "in-place ASCII lowercase"),
        ("make_ascii_uppercase", "in-place ASCII uppercase"),
        ("escape_debug", "escape for debug output"),
        ("escape_default", "escape for default output"),
        ("escape_unicode", "escape to unicode format"),
        ("encode_utf8", "encode char to UTF-8 bytes"),
        ("encode_utf16", "encode to UTF-16"),
    ]:
        SIGNATURES.append(("core", ["str", method], purpose, "rust_str"))

    # core::num (integer methods)
    for int_type in ["i8", "i16", "i32", "i64", "i128", "isize",
                     "u8", "u16", "u32", "u64", "u128", "usize"]:
        for method, purpose in [
            ("wrapping_add", f"{int_type} wrapping addition"),
            ("wrapping_sub", f"{int_type} wrapping subtraction"),
            ("wrapping_mul", f"{int_type} wrapping multiplication"),
            ("saturating_add", f"{int_type} saturating addition"),
            ("saturating_sub", f"{int_type} saturating subtraction"),
            ("saturating_mul", f"{int_type} saturating multiplication"),
            ("checked_add", f"{int_type} checked addition"),
            ("checked_sub", f"{int_type} checked subtraction"),
            ("checked_mul", f"{int_type} checked multiplication"),
            ("checked_div", f"{int_type} checked division"),
            ("overflowing_add", f"{int_type} overflowing addition"),
            ("overflowing_sub", f"{int_type} overflowing subtraction"),
            ("overflowing_mul", f"{int_type} overflowing multiplication"),
            ("pow", f"{int_type} exponentiation"),
            ("count_ones", f"{int_type} popcount"),
            ("count_zeros", f"{int_type} count zero bits"),
            ("leading_zeros", f"{int_type} count leading zeros"),
            ("trailing_zeros", f"{int_type} count trailing zeros"),
            ("leading_ones", f"{int_type} count leading ones"),
            ("trailing_ones", f"{int_type} count trailing ones"),
            ("rotate_left", f"{int_type} bitwise rotate left"),
            ("rotate_right", f"{int_type} bitwise rotate right"),
            ("swap_bytes", f"{int_type} swap byte order"),
            ("reverse_bits", f"{int_type} reverse bit order"),
            ("from_be", f"{int_type} from big-endian"),
            ("from_le", f"{int_type} from little-endian"),
            ("to_be", f"{int_type} to big-endian"),
            ("to_le", f"{int_type} to little-endian"),
            ("to_be_bytes", f"{int_type} to big-endian bytes"),
            ("to_le_bytes", f"{int_type} to little-endian bytes"),
            ("to_ne_bytes", f"{int_type} to native-endian bytes"),
            ("from_be_bytes", f"{int_type} from big-endian bytes"),
            ("from_le_bytes", f"{int_type} from little-endian bytes"),
            ("from_ne_bytes", f"{int_type} from native-endian bytes"),
            ("from_str_radix", f"parse {int_type} from string with radix"),
        ]:
            SIGNATURES.append(("core", ["num", int_type, method], purpose, "rust_num"))

    # core::num float methods
    for float_type in ["f32", "f64"]:
        for method, purpose in [
            ("floor", f"{float_type} round down"),
            ("ceil", f"{float_type} round up"),
            ("round", f"{float_type} round to nearest"),
            ("trunc", f"{float_type} truncate to integer part"),
            ("fract", f"{float_type} fractional part"),
            ("abs", f"{float_type} absolute value"),
            ("signum", f"{float_type} sign function"),
            ("copysign", f"{float_type} copy sign"),
            ("mul_add", f"{float_type} fused multiply-add"),
            ("div_euclid", f"{float_type} euclidean division"),
            ("rem_euclid", f"{float_type} euclidean remainder"),
            ("powi", f"{float_type} integer power"),
            ("powf", f"{float_type} float power"),
            ("sqrt", f"{float_type} square root"),
            ("cbrt", f"{float_type} cube root"),
            ("exp", f"{float_type} exponential"),
            ("exp2", f"{float_type} base-2 exponential"),
            ("ln", f"{float_type} natural logarithm"),
            ("log", f"{float_type} logarithm with base"),
            ("log2", f"{float_type} base-2 logarithm"),
            ("log10", f"{float_type} base-10 logarithm"),
            ("hypot", f"{float_type} hypotenuse"),
            ("sin", f"{float_type} sine"),
            ("cos", f"{float_type} cosine"),
            ("tan", f"{float_type} tangent"),
            ("asin", f"{float_type} arc sine"),
            ("acos", f"{float_type} arc cosine"),
            ("atan", f"{float_type} arc tangent"),
            ("atan2", f"{float_type} two-argument arc tangent"),
            ("sinh", f"{float_type} hyperbolic sine"),
            ("cosh", f"{float_type} hyperbolic cosine"),
            ("tanh", f"{float_type} hyperbolic tangent"),
            ("asinh", f"{float_type} inverse hyperbolic sine"),
            ("acosh", f"{float_type} inverse hyperbolic cosine"),
            ("atanh", f"{float_type} inverse hyperbolic tangent"),
            ("is_nan", f"check if {float_type} is NaN"),
            ("is_infinite", f"check if {float_type} is infinite"),
            ("is_finite", f"check if {float_type} is finite"),
            ("is_normal", f"check if {float_type} is normal"),
            ("is_sign_positive", f"check if {float_type} is positive"),
            ("is_sign_negative", f"check if {float_type} is negative"),
            ("is_subnormal", f"check if {float_type} is subnormal"),
            ("min", f"{float_type} minimum"),
            ("max", f"{float_type} maximum"),
            ("clamp", f"clamp {float_type} to range"),
            ("total_cmp", f"{float_type} total ordering comparison"),
            ("to_bits", f"{float_type} to raw bits"),
            ("from_bits", f"raw bits to {float_type}"),
            ("to_radians", f"degrees to radians ({float_type})"),
            ("to_degrees", f"radians to degrees ({float_type})"),
            ("recip", f"{float_type} reciprocal"),
        ]:
            SIGNATURES.append(("core", ["num", float_type, method], purpose, "rust_num"))

    # core::sync::atomic
    for atomic_type in ["AtomicBool", "AtomicI8", "AtomicI16", "AtomicI32",
                        "AtomicI64", "AtomicIsize", "AtomicU8", "AtomicU16",
                        "AtomicU32", "AtomicU64", "AtomicUsize", "AtomicPtr"]:
        for method, purpose in [
            ("new", f"create new {atomic_type}"),
            ("load", f"atomically load {atomic_type}"),
            ("store", f"atomically store {atomic_type}"),
            ("swap", f"atomically swap {atomic_type}"),
            ("compare_exchange", f"atomic compare-and-swap {atomic_type}"),
            ("compare_exchange_weak", f"weak atomic CAS {atomic_type}"),
            ("fetch_add", f"atomic fetch-add {atomic_type}"),
            ("fetch_sub", f"atomic fetch-sub {atomic_type}"),
            ("fetch_and", f"atomic fetch-and {atomic_type}"),
            ("fetch_or", f"atomic fetch-or {atomic_type}"),
            ("fetch_xor", f"atomic fetch-xor {atomic_type}"),
            ("fetch_max", f"atomic fetch-max {atomic_type}"),
            ("fetch_min", f"atomic fetch-min {atomic_type}"),
            ("fetch_update", f"atomic fetch-update {atomic_type}"),
            ("into_inner", f"unwrap {atomic_type} value"),
            ("get_mut", f"get mutable reference to {atomic_type}"),
        ]:
            SIGNATURES.append(("core", ["sync", "atomic", atomic_type, method], purpose, "rust_atomic"))

    # core::simd (portable SIMD)
    for simd_type in ["f32x4", "f32x8", "f32x16", "f64x2", "f64x4", "f64x8",
                      "i8x16", "i8x32", "i16x8", "i16x16", "i32x4", "i32x8",
                      "i64x2", "i64x4", "u8x16", "u8x32", "u16x8", "u32x4",
                      "u64x2", "u64x4", "mask8x16", "mask32x4", "mask64x2"]:
        for method, purpose in [
            ("splat", f"broadcast scalar to all lanes of {simd_type}"),
            ("from_array", f"create {simd_type} from array"),
            ("to_array", f"extract {simd_type} to array"),
            ("from_slice", f"load {simd_type} from slice"),
            ("gather_or", f"gather {simd_type} elements from slice"),
            ("scatter", f"scatter {simd_type} elements to slice"),
            ("reduce_sum", f"horizontal sum of {simd_type}"),
            ("reduce_product", f"horizontal product of {simd_type}"),
            ("reduce_min", f"horizontal min of {simd_type}"),
            ("reduce_max", f"horizontal max of {simd_type}"),
            ("reduce_and", f"horizontal AND of {simd_type}"),
            ("reduce_or", f"horizontal OR of {simd_type}"),
            ("reduce_xor", f"horizontal XOR of {simd_type}"),
            ("simd_eq", f"lane-wise equality of {simd_type}"),
            ("simd_ne", f"lane-wise inequality of {simd_type}"),
            ("simd_lt", f"lane-wise less-than of {simd_type}"),
            ("simd_le", f"lane-wise less-or-equal of {simd_type}"),
            ("simd_gt", f"lane-wise greater-than of {simd_type}"),
            ("simd_ge", f"lane-wise greater-or-equal of {simd_type}"),
            ("abs", f"lane-wise absolute value of {simd_type}"),
            ("lanes", f"number of lanes in {simd_type}"),
            ("swizzle", f"rearrange lanes of {simd_type}"),
            ("reverse", f"reverse lanes of {simd_type}"),
            ("rotate_lanes_left", f"rotate lanes left of {simd_type}"),
            ("rotate_lanes_right", f"rotate lanes right of {simd_type}"),
            ("interleave", f"interleave two {simd_type} vectors"),
            ("deinterleave", f"deinterleave {simd_type} into two vectors"),
        ]:
            SIGNATURES.append(("core", ["simd", simd_type, method], purpose, "rust_simd"))

    # -------------------------------------------------------------------------
    # ALLOC CRATE (alloc::)
    # -------------------------------------------------------------------------

    # Vec
    for method, purpose in [
        ("new", "create empty Vec"),
        ("with_capacity", "create Vec with preallocated capacity"),
        ("from_raw_parts", "create Vec from raw pointer (unsafe)"),
        ("capacity", "return allocated capacity"),
        ("reserve", "reserve additional capacity"),
        ("reserve_exact", "reserve exact additional capacity"),
        ("try_reserve", "try to reserve additional capacity"),
        ("shrink_to_fit", "shrink capacity to length"),
        ("shrink_to", "shrink capacity to at least given"),
        ("into_boxed_slice", "convert to boxed slice"),
        ("truncate", "truncate to length"),
        ("as_slice", "get slice view"),
        ("as_mut_slice", "get mutable slice view"),
        ("as_ptr", "get raw pointer to data"),
        ("as_mut_ptr", "get mutable raw pointer to data"),
        ("set_len", "set length without checking (unsafe)"),
        ("swap_remove", "remove element swapping with last"),
        ("insert", "insert element at index"),
        ("remove", "remove and return element at index"),
        ("retain", "keep elements matching predicate"),
        ("retain_mut", "keep elements matching mutable predicate"),
        ("dedup", "remove consecutive duplicates"),
        ("dedup_by", "remove consecutive duplicates by comparator"),
        ("dedup_by_key", "remove consecutive duplicates by key"),
        ("push", "append element to end"),
        ("pop", "remove and return last element"),
        ("append", "move all elements from other Vec"),
        ("drain", "remove range returning iterator"),
        ("clear", "remove all elements"),
        ("len", "return number of elements"),
        ("is_empty", "check if Vec is empty"),
        ("split_off", "split Vec at index"),
        ("resize", "resize Vec filling with value"),
        ("resize_with", "resize Vec filling with closure"),
        ("extend_from_slice", "append elements from slice"),
        ("extend_from_within", "append elements from self range"),
        ("leak", "leak Vec returning mutable slice"),
        ("spare_capacity_mut", "get spare capacity as MaybeUninit slice"),
    ]:
        SIGNATURES.append(("alloc", ["vec", "Vec", method], purpose, "rust_vec"))

    # String
    for method, purpose in [
        ("new", "create empty String"),
        ("with_capacity", "create String with preallocated capacity"),
        ("from_utf8", "create String from UTF-8 bytes"),
        ("from_utf8_lossy", "create String from UTF-8 with replacement"),
        ("from_utf8_unchecked", "create String from UTF-8 (unsafe)"),
        ("from_utf16", "create String from UTF-16"),
        ("from_utf16_lossy", "create String from UTF-16 with replacement"),
        ("into_bytes", "convert String to byte Vec"),
        ("as_str", "get &str from String"),
        ("as_mut_str", "get &mut str from String"),
        ("push_str", "append string slice"),
        ("push", "append character"),
        ("capacity", "return allocated capacity"),
        ("reserve", "reserve additional capacity"),
        ("reserve_exact", "reserve exact additional capacity"),
        ("try_reserve", "try to reserve additional capacity"),
        ("shrink_to_fit", "shrink capacity to length"),
        ("shrink_to", "shrink capacity to at least given"),
        ("truncate", "truncate to byte length"),
        ("pop", "remove and return last character"),
        ("remove", "remove character at byte index"),
        ("retain", "keep characters matching predicate"),
        ("insert", "insert character at byte index"),
        ("insert_str", "insert string at byte index"),
        ("as_bytes", "get bytes as slice"),
        ("len", "return byte length"),
        ("is_empty", "check if String is empty"),
        ("clear", "remove all content"),
        ("drain", "remove byte range returning iterator"),
        ("replace_range", "replace byte range with string"),
        ("into_boxed_str", "convert to boxed str"),
        ("leak", "leak String returning mutable str"),
    ]:
        SIGNATURES.append(("alloc", ["string", "String", method], purpose, "rust_string"))

    # Box
    for method, purpose in [
        ("new", "allocate value on heap"),
        ("new_uninit", "allocate uninitialized on heap"),
        ("new_zeroed", "allocate zero-initialized on heap"),
        ("pin", "allocate and pin on heap"),
        ("into_raw", "consume Box returning raw pointer"),
        ("from_raw", "create Box from raw pointer (unsafe)"),
        ("leak", "leak Box returning mutable reference"),
        ("into_inner", "unwrap boxed value"),
        ("into_boxed_slice", "convert Box<[T; N]> to Box<[T]>"),
        ("downcast", "attempt to downcast Box<dyn Any>"),
    ]:
        SIGNATURES.append(("alloc", ["boxed", "Box", method], purpose, "rust_box"))

    # Rc
    for method, purpose in [
        ("new", "create new Rc"),
        ("new_uninit", "create new uninitialized Rc"),
        ("pin", "create new pinned Rc"),
        ("try_unwrap", "try to unwrap Rc to inner"),
        ("into_raw", "consume Rc returning raw pointer"),
        ("from_raw", "create Rc from raw pointer (unsafe)"),
        ("downgrade", "create Weak from Rc"),
        ("strong_count", "get strong reference count"),
        ("weak_count", "get weak reference count"),
        ("ptr_eq", "check if two Rcs point to same allocation"),
        ("make_mut", "get mutable reference (clone if needed)"),
        ("get_mut", "get mutable reference if unique"),
        ("clone", "increment reference count"),
        ("into_inner", "unwrap Rc if unique"),
    ]:
        SIGNATURES.append(("alloc", ["rc", "Rc", method], purpose, "rust_rc"))

    # Arc
    for method, purpose in [
        ("new", "create new Arc"),
        ("new_uninit", "create new uninitialized Arc"),
        ("pin", "create new pinned Arc"),
        ("try_unwrap", "try to unwrap Arc to inner"),
        ("into_raw", "consume Arc returning raw pointer"),
        ("from_raw", "create Arc from raw pointer (unsafe)"),
        ("downgrade", "create Weak from Arc"),
        ("strong_count", "get strong reference count"),
        ("weak_count", "get weak reference count"),
        ("ptr_eq", "check if two Arcs point to same allocation"),
        ("make_mut", "get mutable reference (clone if needed)"),
        ("get_mut", "get mutable reference if unique"),
        ("clone", "increment atomic reference count"),
        ("into_inner", "unwrap Arc if unique"),
    ]:
        SIGNATURES.append(("alloc", ["sync", "Arc", method], purpose, "rust_arc"))

    # BTreeMap / BTreeSet
    for method, purpose in [
        ("new", "create empty BTreeMap"),
        ("insert", "insert key-value pair"),
        ("remove", "remove by key"),
        ("get", "get reference by key"),
        ("get_mut", "get mutable reference by key"),
        ("get_key_value", "get key-value pair by key"),
        ("contains_key", "check if key exists"),
        ("len", "return number of entries"),
        ("is_empty", "check if map is empty"),
        ("clear", "remove all entries"),
        ("entry", "get entry for in-place manipulation"),
        ("keys", "get key iterator"),
        ("values", "get value iterator"),
        ("values_mut", "get mutable value iterator"),
        ("iter", "get key-value iterator"),
        ("iter_mut", "get mutable key-value iterator"),
        ("range", "get range iterator"),
        ("range_mut", "get mutable range iterator"),
        ("split_off", "split map at key"),
        ("first_key_value", "get first key-value pair"),
        ("last_key_value", "get last key-value pair"),
        ("pop_first", "remove and return first entry"),
        ("pop_last", "remove and return last entry"),
        ("retain", "keep entries matching predicate"),
        ("into_keys", "consume map returning key iterator"),
        ("into_values", "consume map returning value iterator"),
        ("append", "move all entries from other map"),
    ]:
        SIGNATURES.append(("alloc", ["collections", "BTreeMap", method], purpose, "rust_btree"))

    for method, purpose in [
        ("new", "create empty BTreeSet"),
        ("insert", "insert value"),
        ("remove", "remove value"),
        ("contains", "check if value exists"),
        ("get", "get reference to value"),
        ("len", "return number of elements"),
        ("is_empty", "check if set is empty"),
        ("clear", "remove all elements"),
        ("first", "get first element"),
        ("last", "get last element"),
        ("pop_first", "remove and return first element"),
        ("pop_last", "remove and return last element"),
        ("iter", "get iterator"),
        ("range", "get range iterator"),
        ("difference", "get set difference iterator"),
        ("symmetric_difference", "get symmetric difference iterator"),
        ("intersection", "get intersection iterator"),
        ("union", "get union iterator"),
        ("is_subset", "check if subset"),
        ("is_superset", "check if superset"),
        ("is_disjoint", "check if disjoint"),
        ("split_off", "split set at value"),
        ("retain", "keep elements matching predicate"),
        ("append", "move all elements from other set"),
    ]:
        SIGNATURES.append(("alloc", ["collections", "BTreeSet", method], purpose, "rust_btree"))

    # VecDeque
    for method, purpose in [
        ("new", "create empty VecDeque"),
        ("with_capacity", "create VecDeque with capacity"),
        ("push_front", "add element to front"),
        ("push_back", "add element to back"),
        ("pop_front", "remove element from front"),
        ("pop_back", "remove element from back"),
        ("front", "peek at front element"),
        ("back", "peek at back element"),
        ("len", "return number of elements"),
        ("is_empty", "check if deque is empty"),
        ("clear", "remove all elements"),
        ("contains", "check if value exists"),
        ("drain", "remove range returning iterator"),
        ("iter", "get iterator"),
        ("iter_mut", "get mutable iterator"),
        ("reserve", "reserve additional capacity"),
        ("shrink_to_fit", "shrink to fit"),
        ("truncate", "truncate to length"),
        ("make_contiguous", "make underlying storage contiguous"),
        ("rotate_left", "rotate elements left"),
        ("rotate_right", "rotate elements right"),
        ("swap", "swap two elements"),
        ("binary_search", "binary search in sorted deque"),
        ("as_slices", "get two slices of underlying data"),
    ]:
        SIGNATURES.append(("alloc", ["collections", "VecDeque", method], purpose, "rust_deque"))

    # LinkedList
    for method, purpose in [
        ("new", "create empty LinkedList"),
        ("push_front", "add element to front"),
        ("push_back", "add element to back"),
        ("pop_front", "remove element from front"),
        ("pop_back", "remove element from back"),
        ("front", "peek at front element"),
        ("back", "peek at back element"),
        ("len", "return number of elements"),
        ("is_empty", "check if list is empty"),
        ("clear", "remove all elements"),
        ("contains", "check if value exists"),
        ("append", "move all from other list"),
        ("iter", "get iterator"),
        ("iter_mut", "get mutable iterator"),
        ("split_off", "split list at index"),
    ]:
        SIGNATURES.append(("alloc", ["collections", "LinkedList", method], purpose, "rust_list"))

    # BinaryHeap
    for method, purpose in [
        ("new", "create empty BinaryHeap (max-heap)"),
        ("with_capacity", "create BinaryHeap with capacity"),
        ("push", "push element into heap"),
        ("pop", "remove and return max element"),
        ("peek", "peek at max element"),
        ("peek_mut", "peek at max element mutably"),
        ("len", "return number of elements"),
        ("is_empty", "check if heap is empty"),
        ("clear", "remove all elements"),
        ("drain", "drain heap elements"),
        ("into_sorted_vec", "consume into sorted Vec"),
        ("into_vec", "consume into unsorted Vec"),
        ("iter", "get iterator"),
        ("retain", "keep elements matching predicate"),
        ("reserve", "reserve additional capacity"),
        ("shrink_to_fit", "shrink to fit"),
        ("capacity", "return capacity"),
        ("append", "move all from other heap"),
    ]:
        SIGNATURES.append(("alloc", ["collections", "BinaryHeap", method], purpose, "rust_heap"))

    # -------------------------------------------------------------------------
    # STD CRATE (std::)
    # -------------------------------------------------------------------------

    # HashMap
    for method, purpose in [
        ("new", "create empty HashMap"),
        ("with_capacity", "create HashMap with capacity"),
        ("with_hasher", "create HashMap with custom hasher"),
        ("with_capacity_and_hasher", "create HashMap with capacity and hasher"),
        ("capacity", "return allocated capacity"),
        ("keys", "get key iterator"),
        ("values", "get value iterator"),
        ("values_mut", "get mutable value iterator"),
        ("iter", "get key-value iterator"),
        ("iter_mut", "get mutable key-value iterator"),
        ("len", "return number of entries"),
        ("is_empty", "check if map is empty"),
        ("drain", "remove all returning iterator"),
        ("retain", "keep entries matching predicate"),
        ("clear", "remove all entries"),
        ("hasher", "get reference to hasher"),
        ("reserve", "reserve capacity for more entries"),
        ("try_reserve", "try to reserve capacity"),
        ("shrink_to_fit", "shrink capacity to fit"),
        ("shrink_to", "shrink capacity to at least given"),
        ("entry", "get entry for in-place manipulation"),
        ("get", "get reference by key"),
        ("get_mut", "get mutable reference by key"),
        ("get_key_value", "get key-value pair by key"),
        ("contains_key", "check if key exists"),
        ("insert", "insert key-value pair"),
        ("remove", "remove by key returning value"),
        ("remove_entry", "remove returning key-value pair"),
        ("into_keys", "consume map returning key iterator"),
        ("into_values", "consume map returning value iterator"),
    ]:
        SIGNATURES.append(("std", ["collections", "HashMap", method], purpose, "rust_hashmap"))

    # HashSet
    for method, purpose in [
        ("new", "create empty HashSet"),
        ("with_capacity", "create HashSet with capacity"),
        ("with_hasher", "create HashSet with custom hasher"),
        ("capacity", "return allocated capacity"),
        ("iter", "get iterator"),
        ("len", "return number of elements"),
        ("is_empty", "check if set is empty"),
        ("drain", "remove all returning iterator"),
        ("retain", "keep elements matching predicate"),
        ("clear", "remove all elements"),
        ("reserve", "reserve capacity for more elements"),
        ("shrink_to_fit", "shrink capacity to fit"),
        ("contains", "check if value exists"),
        ("get", "get reference to value"),
        ("insert", "insert value"),
        ("replace", "insert and return old value if any"),
        ("remove", "remove value"),
        ("take", "remove and return value"),
        ("difference", "get set difference iterator"),
        ("symmetric_difference", "get symmetric difference iterator"),
        ("intersection", "get intersection iterator"),
        ("union", "get union iterator"),
        ("is_subset", "check if subset"),
        ("is_superset", "check if superset"),
        ("is_disjoint", "check if disjoint"),
    ]:
        SIGNATURES.append(("std", ["collections", "HashSet", method], purpose, "rust_hashset"))

    # std::io
    for method, purpose in [
        ("read", "read bytes into buffer"),
        ("read_to_end", "read all bytes to Vec"),
        ("read_to_string", "read all to String"),
        ("read_exact", "read exact number of bytes"),
        ("read_buf", "read into BorrowedBuf"),
        ("by_ref", "create reference adaptor"),
        ("bytes", "get byte iterator"),
        ("chain", "chain two readers"),
        ("take", "limit bytes from reader"),
        ("write", "write bytes from buffer"),
        ("write_all", "write all bytes"),
        ("write_fmt", "write formatted data"),
        ("flush", "flush output buffer"),
        ("write_vectored", "write from multiple buffers"),
        ("seek", "seek to position"),
        ("rewind", "seek to beginning"),
        ("stream_position", "get current position"),
        ("copy", "copy reader to writer"),
        ("stdin", "get stdin handle"),
        ("stdout", "get stdout handle"),
        ("stderr", "get stderr handle"),
        ("empty", "create empty reader"),
        ("sink", "create sink writer"),
        ("repeat", "create repeating byte reader"),
        ("BufReader", "buffered reader wrapper"),
        ("BufWriter", "buffered writer wrapper"),
        ("LineWriter", "line-buffered writer wrapper"),
        ("Cursor", "in-memory I/O cursor"),
    ]:
        SIGNATURES.append(("std", ["io", method], purpose, "rust_io"))

    # std::fs
    for method, purpose in [
        ("read", "read entire file to Vec"),
        ("read_to_string", "read entire file to String"),
        ("write", "write bytes to file"),
        ("create_dir", "create directory"),
        ("create_dir_all", "create directory recursively"),
        ("remove_dir", "remove empty directory"),
        ("remove_dir_all", "remove directory recursively"),
        ("remove_file", "remove file"),
        ("rename", "rename/move file"),
        ("copy", "copy file"),
        ("hard_link", "create hard link"),
        ("symlink", "create symlink"),
        ("metadata", "get file metadata"),
        ("symlink_metadata", "get symlink metadata"),
        ("read_link", "read symlink target"),
        ("canonicalize", "resolve to absolute path"),
        ("read_dir", "iterate directory entries"),
        ("set_permissions", "set file permissions"),
        ("exists", "check if path exists"),
        ("File", "open file for reading/writing"),
    ]:
        SIGNATURES.append(("std", ["fs", method], purpose, "rust_fs"))

    for method, purpose in [
        ("open", "open file for reading"),
        ("create", "create file for writing"),
        ("create_new", "create new file (error if exists)"),
        ("options", "get OpenOptions builder"),
        ("metadata", "get file metadata"),
        ("try_clone", "clone file handle"),
        ("set_len", "set file size"),
        ("set_permissions", "set file permissions"),
        ("sync_all", "sync all data and metadata"),
        ("sync_data", "sync data only"),
    ]:
        SIGNATURES.append(("std", ["fs", "File", method], purpose, "rust_fs"))

    # std::path
    for method, purpose in [
        ("new", "create Path from string"),
        ("as_os_str", "get as OsStr"),
        ("to_str", "convert to str"),
        ("to_path_buf", "convert to PathBuf"),
        ("is_absolute", "check if absolute path"),
        ("is_relative", "check if relative path"),
        ("has_root", "check if has root"),
        ("parent", "get parent directory"),
        ("ancestors", "get ancestor iterator"),
        ("file_name", "get file name"),
        ("file_stem", "get file stem (no extension)"),
        ("extension", "get file extension"),
        ("join", "join two paths"),
        ("with_file_name", "replace file name"),
        ("with_extension", "replace extension"),
        ("components", "get path component iterator"),
        ("display", "get displayable path"),
        ("exists", "check if path exists"),
        ("is_file", "check if path is file"),
        ("is_dir", "check if path is directory"),
        ("is_symlink", "check if path is symlink"),
        ("metadata", "get metadata"),
        ("read_dir", "read directory"),
        ("read_link", "read symlink"),
        ("canonicalize", "resolve to canonical path"),
        ("starts_with", "check path prefix"),
        ("ends_with", "check path suffix"),
        ("strip_prefix", "strip path prefix"),
    ]:
        SIGNATURES.append(("std", ["path", "Path", method], purpose, "rust_path"))

    for method, purpose in [
        ("new", "create empty PathBuf"),
        ("push", "append path component"),
        ("pop", "remove last component"),
        ("set_file_name", "set file name"),
        ("set_extension", "set file extension"),
        ("as_path", "get Path reference"),
        ("into_os_string", "convert to OsString"),
        ("capacity", "return allocated capacity"),
        ("clear", "clear to empty"),
        ("reserve", "reserve capacity"),
        ("shrink_to_fit", "shrink to fit"),
    ]:
        SIGNATURES.append(("std", ["path", "PathBuf", method], purpose, "rust_path"))

    # std::net
    for method, purpose in [
        ("connect", "connect TCP stream"),
        ("peer_addr", "get peer address"),
        ("local_addr", "get local address"),
        ("shutdown", "shutdown connection"),
        ("try_clone", "clone TCP stream"),
        ("set_read_timeout", "set read timeout"),
        ("set_write_timeout", "set write timeout"),
        ("set_nodelay", "set TCP_NODELAY"),
        ("set_nonblocking", "set non-blocking mode"),
        ("set_ttl", "set IP TTL"),
        ("peek", "peek at incoming data"),
        ("read_timeout", "get read timeout"),
        ("write_timeout", "get write timeout"),
    ]:
        SIGNATURES.append(("std", ["net", "TcpStream", method], purpose, "rust_net"))

    for method, purpose in [
        ("bind", "bind to local address"),
        ("local_addr", "get local address"),
        ("accept", "accept incoming connection"),
        ("incoming", "get incoming connections iterator"),
        ("set_nonblocking", "set non-blocking mode"),
        ("set_ttl", "set IP TTL"),
        ("try_clone", "clone listener"),
    ]:
        SIGNATURES.append(("std", ["net", "TcpListener", method], purpose, "rust_net"))

    for method, purpose in [
        ("bind", "bind to local address"),
        ("send_to", "send data to address"),
        ("recv_from", "receive data with source address"),
        ("send", "send data to connected peer"),
        ("recv", "receive data from connected peer"),
        ("connect", "connect to remote address"),
        ("peek_from", "peek at incoming data with source"),
        ("local_addr", "get local address"),
        ("peer_addr", "get peer address"),
        ("set_nonblocking", "set non-blocking mode"),
        ("set_read_timeout", "set read timeout"),
        ("set_write_timeout", "set write timeout"),
        ("set_broadcast", "enable broadcast"),
        ("set_multicast_loop_v4", "set multicast loopback"),
        ("join_multicast_v4", "join multicast group"),
        ("leave_multicast_v4", "leave multicast group"),
        ("set_ttl", "set IP TTL"),
        ("try_clone", "clone socket"),
    ]:
        SIGNATURES.append(("std", ["net", "UdpSocket", method], purpose, "rust_net"))

    # std::sync
    for method, purpose in [
        ("new", "create new Mutex"),
        ("lock", "acquire Mutex lock"),
        ("try_lock", "try to acquire Mutex lock"),
        ("is_poisoned", "check if Mutex is poisoned"),
        ("into_inner", "unwrap Mutex value"),
        ("get_mut", "get mutable reference"),
        ("clear_poison", "clear poison flag"),
    ]:
        SIGNATURES.append(("std", ["sync", "Mutex", method], purpose, "rust_sync"))

    for method, purpose in [
        ("new", "create new RwLock"),
        ("read", "acquire read lock"),
        ("write", "acquire write lock"),
        ("try_read", "try to acquire read lock"),
        ("try_write", "try to acquire write lock"),
        ("is_poisoned", "check if RwLock is poisoned"),
        ("into_inner", "unwrap RwLock value"),
        ("get_mut", "get mutable reference"),
        ("clear_poison", "clear poison flag"),
    ]:
        SIGNATURES.append(("std", ["sync", "RwLock", method], purpose, "rust_sync"))

    for method, purpose in [
        ("new", "create new Condvar"),
        ("wait", "block until notified"),
        ("wait_while", "block until predicate false"),
        ("wait_timeout", "block with timeout"),
        ("wait_timeout_while", "block with timeout and predicate"),
        ("notify_one", "wake one waiting thread"),
        ("notify_all", "wake all waiting threads"),
    ]:
        SIGNATURES.append(("std", ["sync", "Condvar", method], purpose, "rust_sync"))

    for method, purpose in [
        ("new", "create new Barrier"),
        ("wait", "block until all threads arrive"),
    ]:
        SIGNATURES.append(("std", ["sync", "Barrier", method], purpose, "rust_sync"))

    SIGNATURES.extend([
        ("std", ["sync", "Once", "call_once"], "execute closure exactly once", "rust_sync"),
        ("std", ["sync", "Once", "call_once_force"], "execute closure exactly once (force)", "rust_sync"),
        ("std", ["sync", "Once", "is_completed"], "check if Once has been called", "rust_sync"),
        ("std", ["sync", "OnceLock", "new"], "create new OnceLock", "rust_sync"),
        ("std", ["sync", "OnceLock", "get"], "get reference if initialized", "rust_sync"),
        ("std", ["sync", "OnceLock", "set"], "set value if uninitialized", "rust_sync"),
        ("std", ["sync", "OnceLock", "get_or_init"], "get or initialize value", "rust_sync"),
        ("std", ["sync", "OnceLock", "get_or_try_init"], "get or try to initialize", "rust_sync"),
        ("std", ["sync", "OnceLock", "into_inner"], "unwrap value", "rust_sync"),
    ])

    # std::thread
    for method, purpose in [
        ("spawn", "spawn new OS thread"),
        ("current", "get current thread handle"),
        ("sleep", "sleep current thread for duration"),
        ("sleep_until", "sleep until instant"),
        ("yield_now", "yield current thread timeslice"),
        ("park", "park current thread"),
        ("park_timeout", "park with timeout"),
        ("unpark", "unpark a parked thread"),
        ("panicking", "check if current thread is panicking"),
        ("available_parallelism", "get number of available CPUs"),
    ]:
        SIGNATURES.append(("std", ["thread", method], purpose, "rust_thread"))

    SIGNATURES.extend([
        ("std", ["thread", "JoinHandle", "join"], "wait for thread to finish", "rust_thread"),
        ("std", ["thread", "JoinHandle", "thread"], "get reference to thread", "rust_thread"),
        ("std", ["thread", "JoinHandle", "is_finished"], "check if thread finished", "rust_thread"),
        ("std", ["thread", "Builder", "new"], "create thread builder", "rust_thread"),
        ("std", ["thread", "Builder", "name"], "set thread name", "rust_thread"),
        ("std", ["thread", "Builder", "stack_size"], "set thread stack size", "rust_thread"),
        ("std", ["thread", "Builder", "spawn"], "spawn thread with builder", "rust_thread"),
    ])

    # std::process
    for method, purpose in [
        ("new", "create new Command"),
        ("arg", "add argument"),
        ("args", "add multiple arguments"),
        ("env", "set environment variable"),
        ("envs", "set multiple environment variables"),
        ("env_remove", "remove environment variable"),
        ("env_clear", "clear all environment variables"),
        ("current_dir", "set working directory"),
        ("stdin", "set stdin handle"),
        ("stdout", "set stdout handle"),
        ("stderr", "set stderr handle"),
        ("spawn", "spawn child process"),
        ("output", "run and capture output"),
        ("status", "run and get exit status"),
    ]:
        SIGNATURES.append(("std", ["process", "Command", method], purpose, "rust_process"))

    SIGNATURES.extend([
        ("std", ["process", "exit"], "exit process with code", "rust_process"),
        ("std", ["process", "abort"], "abort process immediately", "rust_process"),
        ("std", ["process", "id"], "get current process ID", "rust_process"),
        ("std", ["process", "Child", "wait"], "wait for child to exit", "rust_process"),
        ("std", ["process", "Child", "kill"], "kill child process", "rust_process"),
        ("std", ["process", "Child", "id"], "get child process ID", "rust_process"),
        ("std", ["process", "Child", "try_wait"], "try to wait for child", "rust_process"),
        ("std", ["process", "Child", "wait_with_output"], "wait and capture output", "rust_process"),
    ])

    # std::env
    for method, purpose in [
        ("args", "get command line arguments iterator"),
        ("args_os", "get command line arguments as OsString"),
        ("var", "get environment variable"),
        ("var_os", "get environment variable as OsString"),
        ("vars", "get all environment variables"),
        ("vars_os", "get all env vars as OsString pairs"),
        ("set_var", "set environment variable"),
        ("remove_var", "remove environment variable"),
        ("current_dir", "get current working directory"),
        ("set_current_dir", "set current working directory"),
        ("current_exe", "get current executable path"),
        ("temp_dir", "get temporary directory path"),
        ("home_dir", "get home directory path"),
        ("consts", "platform constants module"),
    ]:
        SIGNATURES.append(("std", ["env", method], purpose, "rust_env"))

    # std::time
    SIGNATURES.extend([
        ("std", ["time", "Instant", "now"], "get current instant", "rust_time"),
        ("std", ["time", "Instant", "elapsed"], "get duration since creation", "rust_time"),
        ("std", ["time", "Instant", "duration_since"], "get duration between instants", "rust_time"),
        ("std", ["time", "Instant", "checked_add"], "add duration with overflow check", "rust_time"),
        ("std", ["time", "Instant", "checked_sub"], "sub duration with overflow check", "rust_time"),
        ("std", ["time", "SystemTime", "now"], "get current system time", "rust_time"),
        ("std", ["time", "SystemTime", "elapsed"], "get time since creation", "rust_time"),
        ("std", ["time", "SystemTime", "duration_since"], "get duration since epoch/time", "rust_time"),
        ("std", ["time", "Duration", "new"], "create Duration from secs + nanos", "rust_time"),
        ("std", ["time", "Duration", "from_secs"], "create Duration from seconds", "rust_time"),
        ("std", ["time", "Duration", "from_millis"], "create Duration from milliseconds", "rust_time"),
        ("std", ["time", "Duration", "from_micros"], "create Duration from microseconds", "rust_time"),
        ("std", ["time", "Duration", "from_nanos"], "create Duration from nanoseconds", "rust_time"),
        ("std", ["time", "Duration", "from_secs_f32"], "create Duration from f32 seconds", "rust_time"),
        ("std", ["time", "Duration", "from_secs_f64"], "create Duration from f64 seconds", "rust_time"),
        ("std", ["time", "Duration", "as_secs"], "get whole seconds", "rust_time"),
        ("std", ["time", "Duration", "as_millis"], "get as milliseconds", "rust_time"),
        ("std", ["time", "Duration", "as_micros"], "get as microseconds", "rust_time"),
        ("std", ["time", "Duration", "as_nanos"], "get as nanoseconds", "rust_time"),
        ("std", ["time", "Duration", "as_secs_f32"], "get as f32 seconds", "rust_time"),
        ("std", ["time", "Duration", "as_secs_f64"], "get as f64 seconds", "rust_time"),
        ("std", ["time", "Duration", "subsec_millis"], "get subsecond milliseconds", "rust_time"),
        ("std", ["time", "Duration", "subsec_micros"], "get subsecond microseconds", "rust_time"),
        ("std", ["time", "Duration", "subsec_nanos"], "get subsecond nanoseconds", "rust_time"),
        ("std", ["time", "Duration", "checked_add"], "add durations with overflow check", "rust_time"),
        ("std", ["time", "Duration", "checked_sub"], "sub durations with overflow check", "rust_time"),
        ("std", ["time", "Duration", "checked_mul"], "mul duration with overflow check", "rust_time"),
        ("std", ["time", "Duration", "checked_div"], "div duration with overflow check", "rust_time"),
        ("std", ["time", "Duration", "is_zero"], "check if duration is zero", "rust_time"),
        ("std", ["time", "Duration", "saturating_add"], "add durations saturating", "rust_time"),
        ("std", ["time", "Duration", "saturating_sub"], "sub durations saturating", "rust_time"),
        ("std", ["time", "Duration", "saturating_mul"], "mul duration saturating", "rust_time"),
    ])

    # std::panic / alloc::panic
    SIGNATURES.extend([
        ("std", ["panic", "catch_unwind"], "catch unwinding panics", "rust_panic"),
        ("std", ["panic", "resume_unwind"], "resume unwinding panic", "rust_panic"),
        ("std", ["panic", "set_hook"], "set custom panic hook", "rust_panic"),
        ("std", ["panic", "take_hook"], "take panic hook", "rust_panic"),
        ("std", ["panic", "panic_any"], "panic with any payload", "rust_panic"),
        ("std", ["panic", "AssertUnwindSafe"], "assert unwind safety wrapper", "rust_panic"),
        ("std", ["panic", "Location", "caller"], "get caller location", "rust_panic"),
        ("std", ["panic", "Location", "file"], "get panic file path", "rust_panic"),
        ("std", ["panic", "Location", "line"], "get panic line number", "rust_panic"),
        ("std", ["panic", "Location", "column"], "get panic column number", "rust_panic"),
    ])

    # std runtime / lang items
    SIGNATURES.extend([
        ("std", ["rt", "lang_start"], "Rust runtime entry point", "rust_runtime"),
        ("std", ["rt", "lang_start_internal"], "Rust runtime internal entry", "rust_runtime"),
        ("std", ["panicking", "begin_panic"], "begin panic sequence", "rust_runtime"),
        ("std", ["panicking", "begin_panic_handler"], "begin panic handler sequence", "rust_runtime"),
        ("std", ["panicking", "rust_panic_with_hook"], "panic with hook invocation", "rust_runtime"),
        ("std", ["panicking", "panic_count", "increase"], "increment panic count", "rust_runtime"),
        ("std", ["panicking", "panic_count", "decrease"], "decrement panic count", "rust_runtime"),
        ("std", ["panicking", "try"], "try to catch panic (internal)", "rust_runtime"),
        ("std", ["alloc", "rust_oom"], "out of memory handler", "rust_runtime"),
        ("std", ["sys_common", "thread_info", "set"], "set thread info", "rust_runtime"),
    ])

    # Rust runtime symbols (mangled form found in binaries)
    RUNTIME_SYMBOLS = {
        "__rust_alloc": ("alloc", "global allocator alloc", "rust_runtime"),
        "__rust_dealloc": ("alloc", "global allocator dealloc", "rust_runtime"),
        "__rust_realloc": ("alloc", "global allocator realloc", "rust_runtime"),
        "__rust_alloc_zeroed": ("alloc", "global allocator alloc zeroed", "rust_runtime"),
        "__rust_alloc_error_handler": ("alloc", "allocation error handler", "rust_runtime"),
        "__rust_no_alloc_shim_is_unstable_v2": ("alloc", "alloc shim version marker", "rust_runtime"),
        "__rust_alloc_error_handler_should_panic_v2": ("alloc", "alloc error panic policy", "rust_runtime"),
        "__rdl_alloc": ("alloc", "default allocator alloc", "rust_runtime"),
        "__rdl_dealloc": ("alloc", "default allocator dealloc", "rust_runtime"),
        "__rdl_realloc": ("alloc", "default allocator realloc", "rust_runtime"),
        "__rdl_alloc_zeroed": ("alloc", "default allocator alloc zeroed", "rust_runtime"),
        "rust_panic": ("std", "Rust panic entry point", "rust_runtime"),
        "rust_begin_unwind": ("std", "begin stack unwinding", "rust_runtime"),
        "__rust_start_panic": ("std", "start panic propagation", "rust_runtime"),
        "__rust_panic_cleanup": ("std", "cleanup after panic", "rust_runtime"),
        "__rust_drop_panic": ("std", "panic during drop", "rust_runtime"),
        "__rust_foreign_exception": ("std", "foreign exception handling", "rust_runtime"),
    }

    # -------------------------------------------------------------------------
    # POPULAR CRATES
    # -------------------------------------------------------------------------

    # serde
    for method, purpose in [
        ("serialize", "serialize value"),
        ("deserialize", "deserialize value"),
        ("serialize_struct", "begin serializing struct"),
        ("serialize_seq", "begin serializing sequence"),
        ("serialize_map", "begin serializing map"),
        ("serialize_tuple", "begin serializing tuple"),
        ("serialize_unit", "serialize unit value"),
        ("serialize_bool", "serialize boolean"),
        ("serialize_i8", "serialize i8"),
        ("serialize_i16", "serialize i16"),
        ("serialize_i32", "serialize i32"),
        ("serialize_i64", "serialize i64"),
        ("serialize_i128", "serialize i128"),
        ("serialize_u8", "serialize u8"),
        ("serialize_u16", "serialize u16"),
        ("serialize_u32", "serialize u32"),
        ("serialize_u64", "serialize u64"),
        ("serialize_u128", "serialize u128"),
        ("serialize_f32", "serialize f32"),
        ("serialize_f64", "serialize f64"),
        ("serialize_str", "serialize string"),
        ("serialize_bytes", "serialize bytes"),
        ("serialize_none", "serialize None"),
        ("serialize_some", "serialize Some"),
        ("serialize_newtype_struct", "serialize newtype struct"),
        ("serialize_newtype_variant", "serialize newtype variant"),
        ("serialize_tuple_variant", "serialize tuple variant"),
        ("serialize_struct_variant", "serialize struct variant"),
        ("serialize_unit_struct", "serialize unit struct"),
        ("serialize_unit_variant", "serialize unit variant"),
        ("serialize_field", "serialize struct field"),
        ("serialize_element", "serialize sequence element"),
        ("serialize_entry", "serialize map entry"),
        ("end", "end serializing compound"),
    ]:
        SIGNATURES.append(("serde", ["Serializer", method], purpose, "rust_serde"))

    for method, purpose in [
        ("deserialize_any", "deserialize any type"),
        ("deserialize_bool", "deserialize boolean"),
        ("deserialize_i8", "deserialize i8"),
        ("deserialize_i16", "deserialize i16"),
        ("deserialize_i32", "deserialize i32"),
        ("deserialize_i64", "deserialize i64"),
        ("deserialize_u8", "deserialize u8"),
        ("deserialize_u16", "deserialize u16"),
        ("deserialize_u32", "deserialize u32"),
        ("deserialize_u64", "deserialize u64"),
        ("deserialize_f32", "deserialize f32"),
        ("deserialize_f64", "deserialize f64"),
        ("deserialize_str", "deserialize string"),
        ("deserialize_string", "deserialize String"),
        ("deserialize_bytes", "deserialize bytes"),
        ("deserialize_byte_buf", "deserialize byte buffer"),
        ("deserialize_option", "deserialize Option"),
        ("deserialize_unit", "deserialize unit"),
        ("deserialize_seq", "deserialize sequence"),
        ("deserialize_map", "deserialize map"),
        ("deserialize_struct", "deserialize struct"),
        ("deserialize_enum", "deserialize enum"),
        ("deserialize_identifier", "deserialize identifier"),
        ("deserialize_ignored_any", "skip deserialization"),
        ("deserialize_tuple", "deserialize tuple"),
        ("deserialize_newtype_struct", "deserialize newtype struct"),
        ("deserialize_unit_struct", "deserialize unit struct"),
        ("deserialize_tuple_struct", "deserialize tuple struct"),
    ]:
        SIGNATURES.append(("serde", ["Deserializer", method], purpose, "rust_serde"))

    # serde_json
    for method, purpose in [
        ("from_str", "parse JSON from string"),
        ("from_slice", "parse JSON from bytes"),
        ("from_reader", "parse JSON from reader"),
        ("from_value", "deserialize from serde_json::Value"),
        ("to_string", "serialize to JSON string"),
        ("to_string_pretty", "serialize to pretty JSON string"),
        ("to_vec", "serialize to JSON bytes"),
        ("to_vec_pretty", "serialize to pretty JSON bytes"),
        ("to_writer", "serialize JSON to writer"),
        ("to_writer_pretty", "serialize pretty JSON to writer"),
        ("to_value", "serialize to serde_json::Value"),
    ]:
        SIGNATURES.append(("serde_json", [method], purpose, "rust_serde"))

    for method, purpose in [
        ("Null", "JSON null value"),
        ("Bool", "JSON boolean value"),
        ("Number", "JSON number value"),
        ("String", "JSON string value"),
        ("Array", "JSON array value"),
        ("Object", "JSON object value"),
        ("get", "get value by key/index"),
        ("is_null", "check if null"),
        ("is_boolean", "check if boolean"),
        ("is_number", "check if number"),
        ("is_string", "check if string"),
        ("is_array", "check if array"),
        ("is_object", "check if object"),
        ("is_i64", "check if i64"),
        ("is_u64", "check if u64"),
        ("is_f64", "check if f64"),
        ("as_bool", "get as bool"),
        ("as_i64", "get as i64"),
        ("as_u64", "get as u64"),
        ("as_f64", "get as f64"),
        ("as_str", "get as str"),
        ("as_array", "get as array"),
        ("as_object", "get as object"),
        ("pointer", "get value by JSON pointer"),
        ("pointer_mut", "get mutable value by JSON pointer"),
    ]:
        SIGNATURES.append(("serde_json", ["Value", method], purpose, "rust_serde"))

    # tokio (async runtime)
    SIGNATURES.extend([
        ("tokio", ["runtime", "Runtime", "new"], "create new Tokio runtime", "rust_async"),
        ("tokio", ["runtime", "Runtime", "block_on"], "block on async task", "rust_async"),
        ("tokio", ["runtime", "Runtime", "spawn"], "spawn async task on runtime", "rust_async"),
        ("tokio", ["runtime", "Runtime", "shutdown_timeout"], "shutdown runtime with timeout", "rust_async"),
        ("tokio", ["runtime", "Runtime", "enter"], "enter runtime context", "rust_async"),
        ("tokio", ["runtime", "Builder", "new_multi_thread"], "create multi-thread runtime builder", "rust_async"),
        ("tokio", ["runtime", "Builder", "new_current_thread"], "create single-thread runtime builder", "rust_async"),
        ("tokio", ["runtime", "Builder", "worker_threads"], "set worker thread count", "rust_async"),
        ("tokio", ["runtime", "Builder", "enable_all"], "enable all runtime features", "rust_async"),
        ("tokio", ["runtime", "Builder", "build"], "build the runtime", "rust_async"),
        ("tokio", ["spawn"], "spawn async task", "rust_async"),
        ("tokio", ["spawn_blocking"], "spawn blocking task", "rust_async"),
        ("tokio", ["task", "spawn"], "spawn async task", "rust_async"),
        ("tokio", ["task", "spawn_blocking"], "spawn blocking task", "rust_async"),
        ("tokio", ["task", "spawn_local"], "spawn local async task", "rust_async"),
        ("tokio", ["task", "yield_now"], "yield current task", "rust_async"),
        ("tokio", ["task", "JoinHandle", "abort"], "abort spawned task", "rust_async"),
        ("tokio", ["task", "JoinSet", "new"], "create new JoinSet", "rust_async"),
        ("tokio", ["task", "JoinSet", "spawn"], "spawn task in JoinSet", "rust_async"),
        ("tokio", ["task", "JoinSet", "join_next"], "await next task completion", "rust_async"),
        ("tokio", ["task", "JoinSet", "abort_all"], "abort all tasks in JoinSet", "rust_async"),
        ("tokio", ["time", "sleep"], "async sleep for duration", "rust_async"),
        ("tokio", ["time", "timeout"], "apply timeout to future", "rust_async"),
        ("tokio", ["time", "interval"], "create periodic interval", "rust_async"),
        ("tokio", ["time", "Instant", "now"], "get current Tokio instant", "rust_async"),
        ("tokio", ["sync", "Mutex", "new"], "create async Mutex", "rust_async"),
        ("tokio", ["sync", "Mutex", "lock"], "acquire async Mutex lock", "rust_async"),
        ("tokio", ["sync", "Mutex", "try_lock"], "try acquire async Mutex lock", "rust_async"),
        ("tokio", ["sync", "RwLock", "new"], "create async RwLock", "rust_async"),
        ("tokio", ["sync", "RwLock", "read"], "acquire async read lock", "rust_async"),
        ("tokio", ["sync", "RwLock", "write"], "acquire async write lock", "rust_async"),
        ("tokio", ["sync", "Semaphore", "new"], "create async Semaphore", "rust_async"),
        ("tokio", ["sync", "Semaphore", "acquire"], "acquire semaphore permit", "rust_async"),
        ("tokio", ["sync", "Semaphore", "try_acquire"], "try acquire semaphore permit", "rust_async"),
        ("tokio", ["sync", "Notify", "new"], "create async Notify", "rust_async"),
        ("tokio", ["sync", "Notify", "notify_one"], "notify one waiter", "rust_async"),
        ("tokio", ["sync", "Notify", "notify_waiters"], "notify all waiters", "rust_async"),
        ("tokio", ["sync", "Notify", "notified"], "wait for notification", "rust_async"),
        ("tokio", ["sync", "mpsc", "channel"], "create bounded async channel", "rust_async"),
        ("tokio", ["sync", "mpsc", "unbounded_channel"], "create unbounded async channel", "rust_async"),
        ("tokio", ["sync", "mpsc", "Sender", "send"], "send to async channel", "rust_async"),
        ("tokio", ["sync", "mpsc", "Receiver", "recv"], "receive from async channel", "rust_async"),
        ("tokio", ["sync", "oneshot", "channel"], "create oneshot channel", "rust_async"),
        ("tokio", ["sync", "broadcast", "channel"], "create broadcast channel", "rust_async"),
        ("tokio", ["sync", "watch", "channel"], "create watch channel", "rust_async"),
        ("tokio", ["io", "AsyncReadExt", "read"], "async read bytes", "rust_async_io"),
        ("tokio", ["io", "AsyncReadExt", "read_to_end"], "async read all to Vec", "rust_async_io"),
        ("tokio", ["io", "AsyncReadExt", "read_to_string"], "async read all to String", "rust_async_io"),
        ("tokio", ["io", "AsyncReadExt", "read_exact"], "async read exact bytes", "rust_async_io"),
        ("tokio", ["io", "AsyncWriteExt", "write"], "async write bytes", "rust_async_io"),
        ("tokio", ["io", "AsyncWriteExt", "write_all"], "async write all bytes", "rust_async_io"),
        ("tokio", ["io", "AsyncWriteExt", "flush"], "async flush", "rust_async_io"),
        ("tokio", ["io", "AsyncWriteExt", "shutdown"], "async shutdown writer", "rust_async_io"),
        ("tokio", ["io", "copy"], "async copy reader to writer", "rust_async_io"),
        ("tokio", ["io", "duplex"], "create in-memory async duplex stream", "rust_async_io"),
        ("tokio", ["net", "TcpListener", "bind"], "async TCP bind", "rust_async_net"),
        ("tokio", ["net", "TcpListener", "accept"], "async TCP accept", "rust_async_net"),
        ("tokio", ["net", "TcpStream", "connect"], "async TCP connect", "rust_async_net"),
        ("tokio", ["net", "UdpSocket", "bind"], "async UDP bind", "rust_async_net"),
        ("tokio", ["net", "UdpSocket", "send_to"], "async UDP send", "rust_async_net"),
        ("tokio", ["net", "UdpSocket", "recv_from"], "async UDP receive", "rust_async_net"),
        ("tokio", ["fs", "read"], "async read file", "rust_async_fs"),
        ("tokio", ["fs", "read_to_string"], "async read file to string", "rust_async_fs"),
        ("tokio", ["fs", "write"], "async write file", "rust_async_fs"),
        ("tokio", ["fs", "create_dir"], "async create directory", "rust_async_fs"),
        ("tokio", ["fs", "create_dir_all"], "async create directory recursively", "rust_async_fs"),
        ("tokio", ["fs", "remove_file"], "async remove file", "rust_async_fs"),
        ("tokio", ["fs", "remove_dir_all"], "async remove directory recursively", "rust_async_fs"),
        ("tokio", ["fs", "rename"], "async rename file", "rust_async_fs"),
        ("tokio", ["fs", "copy"], "async copy file", "rust_async_fs"),
        ("tokio", ["fs", "metadata"], "async get file metadata", "rust_async_fs"),
        ("tokio", ["fs", "File", "open"], "async open file", "rust_async_fs"),
        ("tokio", ["fs", "File", "create"], "async create file", "rust_async_fs"),
    ])

    # regex
    SIGNATURES.extend([
        ("regex", ["Regex", "new"], "compile regex pattern", "rust_regex"),
        ("regex", ["Regex", "is_match"], "check if regex matches", "rust_regex"),
        ("regex", ["Regex", "find"], "find first regex match", "rust_regex"),
        ("regex", ["Regex", "find_iter"], "iterate all regex matches", "rust_regex"),
        ("regex", ["Regex", "captures"], "get regex capture groups", "rust_regex"),
        ("regex", ["Regex", "captures_iter"], "iterate capture groups", "rust_regex"),
        ("regex", ["Regex", "replace"], "replace first match", "rust_regex"),
        ("regex", ["Regex", "replace_all"], "replace all matches", "rust_regex"),
        ("regex", ["Regex", "replacen"], "replace first n matches", "rust_regex"),
        ("regex", ["Regex", "split"], "split by regex", "rust_regex"),
        ("regex", ["Regex", "splitn"], "split into n parts by regex", "rust_regex"),
        ("regex", ["Regex", "as_str"], "get regex pattern string", "rust_regex"),
        ("regex", ["Regex", "captures_len"], "get number of capture groups", "rust_regex"),
        ("regex", ["RegexSet", "new"], "compile regex set", "rust_regex"),
        ("regex", ["RegexSet", "is_match"], "check if any regex matches", "rust_regex"),
        ("regex", ["RegexSet", "matches"], "get matching regex indices", "rust_regex"),
        ("regex", ["bytes", "Regex", "new"], "compile byte regex", "rust_regex"),
        ("regex", ["bytes", "Regex", "is_match"], "check if byte regex matches", "rust_regex"),
        ("regex", ["bytes", "Regex", "find"], "find byte regex match", "rust_regex"),
    ])

    # clap (CLI parsing)
    SIGNATURES.extend([
        ("clap", ["Command", "new"], "create new CLI command", "rust_cli"),
        ("clap", ["Command", "arg"], "add argument to command", "rust_cli"),
        ("clap", ["Command", "args"], "add multiple arguments", "rust_cli"),
        ("clap", ["Command", "subcommand"], "add subcommand", "rust_cli"),
        ("clap", ["Command", "about"], "set command description", "rust_cli"),
        ("clap", ["Command", "version"], "set command version", "rust_cli"),
        ("clap", ["Command", "author"], "set command author", "rust_cli"),
        ("clap", ["Command", "get_matches"], "parse CLI args", "rust_cli"),
        ("clap", ["Command", "try_get_matches"], "try parse CLI args", "rust_cli"),
        ("clap", ["Arg", "new"], "create new CLI argument", "rust_cli"),
        ("clap", ["Arg", "short"], "set short flag", "rust_cli"),
        ("clap", ["Arg", "long"], "set long flag", "rust_cli"),
        ("clap", ["Arg", "value_name"], "set value name", "rust_cli"),
        ("clap", ["Arg", "help"], "set help text", "rust_cli"),
        ("clap", ["Arg", "required"], "set argument required", "rust_cli"),
        ("clap", ["Arg", "default_value"], "set default value", "rust_cli"),
        ("clap", ["Arg", "action"], "set argument action", "rust_cli"),
        ("clap", ["Arg", "num_args"], "set number of values", "rust_cli"),
        ("clap", ["Arg", "value_parser"], "set value parser", "rust_cli"),
        ("clap", ["ArgMatches", "get_one"], "get single argument value", "rust_cli"),
        ("clap", ["ArgMatches", "get_many"], "get multiple argument values", "rust_cli"),
        ("clap", ["ArgMatches", "get_flag"], "get boolean flag value", "rust_cli"),
        ("clap", ["ArgMatches", "contains_id"], "check if argument present", "rust_cli"),
        ("clap", ["ArgMatches", "subcommand"], "get matched subcommand", "rust_cli"),
        ("clap", ["Parser", "parse"], "derive-based arg parsing", "rust_cli"),
        ("clap", ["Parser", "try_parse"], "try derive-based arg parsing", "rust_cli"),
    ])

    # log / tracing
    SIGNATURES.extend([
        ("log", ["error"], "log error message", "rust_log"),
        ("log", ["warn"], "log warning message", "rust_log"),
        ("log", ["info"], "log info message", "rust_log"),
        ("log", ["debug"], "log debug message", "rust_log"),
        ("log", ["trace"], "log trace message", "rust_log"),
        ("log", ["log"], "log with level", "rust_log"),
        ("log", ["set_logger"], "set global logger", "rust_log"),
        ("log", ["set_max_level"], "set max log level", "rust_log"),
        ("log", ["max_level"], "get max log level", "rust_log"),
        ("log", ["logger"], "get global logger reference", "rust_log"),
        ("tracing", ["event"], "emit tracing event", "rust_tracing"),
        ("tracing", ["span"], "create tracing span", "rust_tracing"),
        ("tracing", ["error"], "emit error event", "rust_tracing"),
        ("tracing", ["warn"], "emit warning event", "rust_tracing"),
        ("tracing", ["info"], "emit info event", "rust_tracing"),
        ("tracing", ["debug"], "emit debug event", "rust_tracing"),
        ("tracing", ["trace"], "emit trace event", "rust_tracing"),
        ("tracing", ["instrument"], "instrument function with span", "rust_tracing"),
        ("tracing", ["Span", "enter"], "enter tracing span", "rust_tracing"),
        ("tracing", ["Span", "in_scope"], "execute closure in span", "rust_tracing"),
        ("tracing", ["subscriber", "set_global_default"], "set global tracing subscriber", "rust_tracing"),
        ("tracing_subscriber", ["fmt", "init"], "init default tracing subscriber", "rust_tracing"),
        ("tracing_subscriber", ["fmt", "layer"], "create formatting layer", "rust_tracing"),
        ("tracing_subscriber", ["EnvFilter", "new"], "create env-based filter", "rust_tracing"),
        ("tracing_subscriber", ["Registry", "default"], "create default registry", "rust_tracing"),
    ])

    # anyhow / thiserror
    SIGNATURES.extend([
        ("anyhow", ["Error", "new"], "create new anyhow error", "rust_error"),
        ("anyhow", ["Error", "msg"], "create error from message", "rust_error"),
        ("anyhow", ["Error", "context"], "add context to error", "rust_error"),
        ("anyhow", ["Error", "chain"], "iterate error chain", "rust_error"),
        ("anyhow", ["Error", "root_cause"], "get root cause of error", "rust_error"),
        ("anyhow", ["Error", "downcast"], "downcast to concrete type", "rust_error"),
        ("anyhow", ["Error", "downcast_ref"], "downcast reference", "rust_error"),
        ("anyhow", ["Error", "is"], "check if error is type", "rust_error"),
        ("anyhow", ["Context", "context"], "add context to Result", "rust_error"),
        ("anyhow", ["Context", "with_context"], "add lazy context to Result", "rust_error"),
        ("anyhow", ["bail"], "return early with error", "rust_error"),
        ("anyhow", ["ensure"], "ensure condition or return error", "rust_error"),
        ("anyhow", ["anyhow"], "create error from format string", "rust_error"),
    ])

    # rayon (parallel iteration)
    SIGNATURES.extend([
        ("rayon", ["prelude", "IntoParallelIterator", "into_par_iter"], "convert to parallel iterator", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "map"], "parallel map", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "filter"], "parallel filter", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "filter_map"], "parallel filter_map", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "flat_map"], "parallel flat_map", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "reduce"], "parallel reduce", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "fold"], "parallel fold", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "sum"], "parallel sum", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "for_each"], "parallel for_each", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "collect"], "parallel collect", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "any"], "parallel any", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "all"], "parallel all", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "find_any"], "parallel find_any", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "find_first"], "parallel find_first", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "count"], "parallel count", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "min"], "parallel min", "rust_parallel"),
        ("rayon", ["prelude", "ParallelIterator", "max"], "parallel max", "rust_parallel"),
        ("rayon", ["prelude", "ParallelSlice", "par_sort"], "parallel sort", "rust_parallel"),
        ("rayon", ["prelude", "ParallelSlice", "par_sort_by"], "parallel sort by", "rust_parallel"),
        ("rayon", ["prelude", "ParallelSlice", "par_sort_unstable"], "parallel unstable sort", "rust_parallel"),
        ("rayon", ["prelude", "ParallelSliceMut", "par_sort"], "parallel sort (mut)", "rust_parallel"),
        ("rayon", ["prelude", "ParallelSliceMut", "par_sort_by"], "parallel sort by (mut)", "rust_parallel"),
        ("rayon", ["prelude", "ParallelString", "par_chars"], "parallel char iterator", "rust_parallel"),
        ("rayon", ["prelude", "ParallelString", "par_lines"], "parallel line iterator", "rust_parallel"),
        ("rayon", ["join"], "execute two closures in parallel", "rust_parallel"),
        ("rayon", ["scope"], "create parallel scope", "rust_parallel"),
        ("rayon", ["ThreadPoolBuilder", "new"], "create thread pool builder", "rust_parallel"),
        ("rayon", ["ThreadPoolBuilder", "num_threads"], "set thread count", "rust_parallel"),
        ("rayon", ["ThreadPoolBuilder", "build"], "build thread pool", "rust_parallel"),
        ("rayon", ["ThreadPool", "install"], "run closure in pool", "rust_parallel"),
    ])

    # bytes crate
    SIGNATURES.extend([
        ("bytes", ["Bytes", "new"], "create empty Bytes", "rust_bytes"),
        ("bytes", ["Bytes", "from_static"], "create Bytes from static slice", "rust_bytes"),
        ("bytes", ["Bytes", "len"], "get byte length", "rust_bytes"),
        ("bytes", ["Bytes", "is_empty"], "check if empty", "rust_bytes"),
        ("bytes", ["Bytes", "slice"], "get sub-slice", "rust_bytes"),
        ("bytes", ["Bytes", "split_to"], "split off prefix", "rust_bytes"),
        ("bytes", ["Bytes", "split_off"], "split off suffix", "rust_bytes"),
        ("bytes", ["Bytes", "truncate"], "truncate to length", "rust_bytes"),
        ("bytes", ["Bytes", "copy_from_slice"], "create from slice copy", "rust_bytes"),
        ("bytes", ["BytesMut", "new"], "create empty BytesMut", "rust_bytes"),
        ("bytes", ["BytesMut", "with_capacity"], "create BytesMut with capacity", "rust_bytes"),
        ("bytes", ["BytesMut", "freeze"], "convert to immutable Bytes", "rust_bytes"),
        ("bytes", ["BytesMut", "put"], "put bytes", "rust_bytes"),
        ("bytes", ["BytesMut", "put_u8"], "put u8", "rust_bytes"),
        ("bytes", ["BytesMut", "put_u16"], "put u16", "rust_bytes"),
        ("bytes", ["BytesMut", "put_u32"], "put u32", "rust_bytes"),
        ("bytes", ["BytesMut", "put_u64"], "put u64", "rust_bytes"),
        ("bytes", ["BytesMut", "put_u16_le"], "put u16 little-endian", "rust_bytes"),
        ("bytes", ["BytesMut", "put_u32_le"], "put u32 little-endian", "rust_bytes"),
        ("bytes", ["BytesMut", "put_u64_le"], "put u64 little-endian", "rust_bytes"),
        ("bytes", ["BytesMut", "put_i8"], "put i8", "rust_bytes"),
        ("bytes", ["BytesMut", "put_i16"], "put i16", "rust_bytes"),
        ("bytes", ["BytesMut", "put_i32"], "put i32", "rust_bytes"),
        ("bytes", ["BytesMut", "put_i64"], "put i64", "rust_bytes"),
        ("bytes", ["BytesMut", "put_f32"], "put f32", "rust_bytes"),
        ("bytes", ["BytesMut", "put_f64"], "put f64", "rust_bytes"),
        ("bytes", ["BytesMut", "put_slice"], "put byte slice", "rust_bytes"),
        ("bytes", ["BytesMut", "extend_from_slice"], "extend from byte slice", "rust_bytes"),
        ("bytes", ["BytesMut", "split"], "split at current position", "rust_bytes"),
        ("bytes", ["BytesMut", "split_to"], "split off prefix", "rust_bytes"),
        ("bytes", ["BytesMut", "split_off"], "split off suffix", "rust_bytes"),
        ("bytes", ["BytesMut", "truncate"], "truncate to length", "rust_bytes"),
        ("bytes", ["BytesMut", "clear"], "clear buffer", "rust_bytes"),
        ("bytes", ["BytesMut", "reserve"], "reserve capacity", "rust_bytes"),
        ("bytes", ["Buf", "remaining"], "remaining bytes", "rust_bytes"),
        ("bytes", ["Buf", "chunk"], "current contiguous chunk", "rust_bytes"),
        ("bytes", ["Buf", "advance"], "advance read position", "rust_bytes"),
        ("bytes", ["Buf", "get_u8"], "read u8", "rust_bytes"),
        ("bytes", ["Buf", "get_u16"], "read u16", "rust_bytes"),
        ("bytes", ["Buf", "get_u32"], "read u32", "rust_bytes"),
        ("bytes", ["Buf", "get_u64"], "read u64", "rust_bytes"),
        ("bytes", ["BufMut", "remaining_mut"], "remaining writable capacity", "rust_bytes"),
        ("bytes", ["BufMut", "put_u8"], "write u8", "rust_bytes"),
        ("bytes", ["BufMut", "put_u16"], "write u16", "rust_bytes"),
        ("bytes", ["BufMut", "put_u32"], "write u32", "rust_bytes"),
        ("bytes", ["BufMut", "put_u64"], "write u64", "rust_bytes"),
        ("bytes", ["BufMut", "put_slice"], "write byte slice", "rust_bytes"),
    ])

    # hyper / reqwest (HTTP)
    SIGNATURES.extend([
        ("hyper", ["Client", "new"], "create HTTP client", "rust_http"),
        ("hyper", ["Client", "get"], "HTTP GET request", "rust_http"),
        ("hyper", ["Client", "request"], "send HTTP request", "rust_http"),
        ("hyper", ["Request", "new"], "create HTTP request", "rust_http"),
        ("hyper", ["Request", "builder"], "create request builder", "rust_http"),
        ("hyper", ["Request", "method"], "get request method", "rust_http"),
        ("hyper", ["Request", "uri"], "get request URI", "rust_http"),
        ("hyper", ["Request", "headers"], "get request headers", "rust_http"),
        ("hyper", ["Request", "body"], "get request body", "rust_http"),
        ("hyper", ["Response", "new"], "create HTTP response", "rust_http"),
        ("hyper", ["Response", "builder"], "create response builder", "rust_http"),
        ("hyper", ["Response", "status"], "get response status", "rust_http"),
        ("hyper", ["Response", "headers"], "get response headers", "rust_http"),
        ("hyper", ["Response", "body"], "get response body", "rust_http"),
        ("hyper", ["Body", "empty"], "create empty body", "rust_http"),
        ("hyper", ["Body", "from"], "create body from data", "rust_http"),
        ("hyper", ["StatusCode", "OK"], "200 OK status", "rust_http"),
        ("hyper", ["StatusCode", "NOT_FOUND"], "404 Not Found status", "rust_http"),
        ("hyper", ["StatusCode", "INTERNAL_SERVER_ERROR"], "500 Internal Error status", "rust_http"),
        ("reqwest", ["Client", "new"], "create reqwest HTTP client", "rust_http"),
        ("reqwest", ["Client", "get"], "reqwest HTTP GET", "rust_http"),
        ("reqwest", ["Client", "post"], "reqwest HTTP POST", "rust_http"),
        ("reqwest", ["Client", "put"], "reqwest HTTP PUT", "rust_http"),
        ("reqwest", ["Client", "delete"], "reqwest HTTP DELETE", "rust_http"),
        ("reqwest", ["Client", "patch"], "reqwest HTTP PATCH", "rust_http"),
        ("reqwest", ["Client", "head"], "reqwest HTTP HEAD", "rust_http"),
        ("reqwest", ["ClientBuilder", "new"], "create reqwest client builder", "rust_http"),
        ("reqwest", ["ClientBuilder", "timeout"], "set request timeout", "rust_http"),
        ("reqwest", ["ClientBuilder", "default_headers"], "set default headers", "rust_http"),
        ("reqwest", ["ClientBuilder", "build"], "build reqwest client", "rust_http"),
        ("reqwest", ["RequestBuilder", "send"], "send request", "rust_http"),
        ("reqwest", ["RequestBuilder", "header"], "add header", "rust_http"),
        ("reqwest", ["RequestBuilder", "body"], "set body", "rust_http"),
        ("reqwest", ["RequestBuilder", "json"], "set JSON body", "rust_http"),
        ("reqwest", ["RequestBuilder", "form"], "set form body", "rust_http"),
        ("reqwest", ["RequestBuilder", "query"], "add query parameter", "rust_http"),
        ("reqwest", ["RequestBuilder", "bearer_auth"], "set bearer auth", "rust_http"),
        ("reqwest", ["RequestBuilder", "basic_auth"], "set basic auth", "rust_http"),
        ("reqwest", ["Response", "status"], "get response status", "rust_http"),
        ("reqwest", ["Response", "text"], "get response as text", "rust_http"),
        ("reqwest", ["Response", "json"], "deserialize response as JSON", "rust_http"),
        ("reqwest", ["Response", "bytes"], "get response bytes", "rust_http"),
        ("reqwest", ["Response", "headers"], "get response headers", "rust_http"),
        ("reqwest", ["Response", "error_for_status"], "error if non-success status", "rust_http"),
        ("reqwest", ["get"], "quick GET request", "rust_http"),
    ])

    # rand
    SIGNATURES.extend([
        ("rand", ["thread_rng"], "get thread-local random generator", "rust_rand"),
        ("rand", ["random"], "generate random value", "rust_rand"),
        ("rand", ["Rng", "gen"], "generate random value", "rust_rand"),
        ("rand", ["Rng", "gen_range"], "generate random in range", "rust_rand"),
        ("rand", ["Rng", "gen_bool"], "generate random boolean", "rust_rand"),
        ("rand", ["Rng", "gen_ratio"], "generate bool with ratio", "rust_rand"),
        ("rand", ["Rng", "fill"], "fill buffer with random bytes", "rust_rand"),
        ("rand", ["Rng", "sample"], "sample from distribution", "rust_rand"),
        ("rand", ["Rng", "shuffle"], "shuffle slice randomly", "rust_rand"),
        ("rand", ["rngs", "StdRng", "from_entropy"], "create StdRng from entropy", "rust_rand"),
        ("rand", ["rngs", "StdRng", "seed_from_u64"], "create StdRng from seed", "rust_rand"),
        ("rand", ["rngs", "SmallRng", "from_entropy"], "create SmallRng from entropy", "rust_rand"),
        ("rand", ["rngs", "OsRng"], "OS random number generator", "rust_rand"),
        ("rand", ["seq", "SliceRandom", "choose"], "choose random element from slice", "rust_rand"),
        ("rand", ["seq", "SliceRandom", "choose_multiple"], "choose multiple random elements", "rust_rand"),
        ("rand", ["seq", "SliceRandom", "shuffle"], "shuffle slice randomly", "rust_rand"),
        ("rand", ["seq", "IteratorRandom", "choose"], "choose random from iterator", "rust_rand"),
        ("rand", ["distributions", "Uniform", "new"], "create uniform distribution", "rust_rand"),
        ("rand", ["distributions", "Standard"], "standard distribution", "rust_rand"),
    ])

    # crossbeam
    SIGNATURES.extend([
        ("crossbeam", ["channel", "unbounded"], "create unbounded crossbeam channel", "rust_parallel"),
        ("crossbeam", ["channel", "bounded"], "create bounded crossbeam channel", "rust_parallel"),
        ("crossbeam", ["channel", "Sender", "send"], "send to crossbeam channel", "rust_parallel"),
        ("crossbeam", ["channel", "Receiver", "recv"], "receive from crossbeam channel", "rust_parallel"),
        ("crossbeam", ["channel", "Receiver", "try_recv"], "try receive from channel", "rust_parallel"),
        ("crossbeam", ["channel", "Receiver", "recv_timeout"], "receive with timeout", "rust_parallel"),
        ("crossbeam", ["channel", "select"], "select over multiple channels", "rust_parallel"),
        ("crossbeam", ["scope"], "create scoped thread scope", "rust_parallel"),
        ("crossbeam", ["epoch", "pin"], "pin current thread epoch", "rust_parallel"),
        ("crossbeam", ["epoch", "Guard", "defer"], "defer action until garbage collection", "rust_parallel"),
        ("crossbeam", ["deque", "Worker", "new_fifo"], "create FIFO work-stealing deque", "rust_parallel"),
        ("crossbeam", ["deque", "Worker", "new_lifo"], "create LIFO work-stealing deque", "rust_parallel"),
        ("crossbeam", ["deque", "Worker", "push"], "push to worker deque", "rust_parallel"),
        ("crossbeam", ["deque", "Worker", "pop"], "pop from worker deque", "rust_parallel"),
        ("crossbeam", ["deque", "Stealer", "steal"], "steal from deque", "rust_parallel"),
        ("crossbeam", ["deque", "Stealer", "steal_batch"], "steal batch from deque", "rust_parallel"),
        ("crossbeam", ["utils", "Backoff", "new"], "create exponential backoff", "rust_parallel"),
        ("crossbeam", ["utils", "Backoff", "spin"], "spin wait", "rust_parallel"),
        ("crossbeam", ["utils", "Backoff", "snooze"], "light sleep", "rust_parallel"),
        ("crossbeam", ["utils", "CachePadded", "new"], "create cache-line padded value", "rust_parallel"),
    ])

    # -------------------------------------------------------------------------
    # Build the final signature dict
    # -------------------------------------------------------------------------

    for crate, path_parts, purpose, category in SIGNATURES:
        demangled = f"{crate}::{'::'.join(path_parts)}" if path_parts else crate

        # Legacy mangling key
        legacy_key = mangle_rust_legacy(crate, path_parts)
        sigs[legacy_key] = {
            "lib": crate,
            "purpose": demangled,
            "category": category,
        }

        # v0 mangling key
        v0_key = mangle_rust_v0_path(crate, path_parts)
        sigs[v0_key] = {
            "lib": crate,
            "purpose": demangled,
            "category": category,
        }

    # Runtime symbols (direct, no mangling needed)
    for sym, (lib, purpose, category) in RUNTIME_SYMBOLS.items():
        sigs[sym] = {
            "lib": lib,
            "purpose": purpose,
            "category": category,
        }

    return sigs


# ============================================================================
# BOLUM 5: Ana Calisma
# ============================================================================

def find_rust_binaries() -> list[tuple[str, str]]:
    """Homebrew'daki Rust binary'leri bul."""
    binaries = []
    homebrew_bin = "/opt/homebrew/bin"

    if not os.path.isdir(homebrew_bin):
        return binaries

    # Bilinen Rust binary'ler
    known_rust = [
        "rg", "fd", "bat", "exa", "eza", "tokei", "hyperfine",
        "delta", "gitui", "zoxide", "dust", "procs", "sd",
        "starship", "bottom", "btm", "nushell", "nu",
        "alacritty", "helix", "hx", "just", "watchexec",
        "cargo-watch", "cargo-edit", "tectonic", "mdbook",
        "cross", "sccache", "trunk", "wasm-pack",
        "difftastic", "difft", "ripgrep", "binwalk",
        "nextonic",
    ]

    # Kesinlikle Rust olmayan binary'ler (C/C++ derleyiciler vs)
    EXCLUDE_PATTERNS = {
        "gcc", "g++", "gfortran", "cpp", "lto-dump", "gcov",
        "c++", "cc", "ld", "as", "ar", "nm", "objdump",
        "objcopy", "ranlib", "strip", "size", "strings",
        "aarch64-apple-darwin",  # cross-compiler prefix
        "quantlib",  # C++ financial library
    }

    for name in known_rust:
        path = os.path.join(homebrew_bin, name)
        if os.path.isfile(path):
            binaries.append((path, name))

    # Ayrica tum binary'leri tara ve Rust-specific sembol icerenleri bul
    found_names = {b[1] for b in binaries}
    try:
        for entry in os.listdir(homebrew_bin):
            path = os.path.join(homebrew_bin, entry)
            if not os.path.isfile(path):
                continue
            if entry in found_names:
                continue

            # Exclude non-Rust binaries
            if any(excl in entry.lower() for excl in EXCLUDE_PATTERNS):
                continue

            # file komutu ile kontrol
            try:
                result = subprocess.run(
                    ["file", path],
                    capture_output=True, text=True, timeout=5
                )
                if "Mach-O" not in result.stdout:
                    continue
            except Exception:
                continue

            # nm ile Rust-specific sembol ara (17h<hash>E pattern)
            try:
                result = subprocess.run(
                    ["nm", "-gU", path],
                    capture_output=True, text=True, timeout=10
                )
                # Rust-specific: hash suffix 17h[0-9a-f]{16}E
                rust_count = sum(1 for line in result.stdout.splitlines()
                               if re.search(r"17h[0-9a-f]{16}E", line))
                if rust_count > 20:
                    binaries.append((path, entry))
            except Exception:
                continue
    except Exception:
        pass

    return binaries


def main():
    print("=" * 60)
    print("Karadul Rust Signature Generator")
    print("=" * 60)

    output_path = "/Users/apple/Desktop/black-widow/sigs/rust_expanded.json"

    # Adim 1: Kapsamli pattern-based signature'lar uret
    print("\n[1/3] Kapsamli stdlib + crate signature'lar uretiliyor...")
    sigs = generate_comprehensive_signatures()
    print(f"  -> {len(sigs)} signature uretildi")

    # Adim 2: Binary'lerden gercek sembol cikart
    print("\n[2/3] Homebrew binary'lerden sembol cikariliyor...")
    binaries = find_rust_binaries()
    print(f"  -> {len(binaries)} Rust binary bulundu: {[b[1] for b in binaries]}")

    binary_sig_count = 0
    for binary_path, binary_name in binaries:
        print(f"  Islem: {binary_name}...", end=" ", flush=True)
        bin_sigs = process_binary_symbols(binary_path, binary_name)
        # Sadece binary'den gelen yeni signature'lari ekle
        new_count = 0
        for key, val in bin_sigs.items():
            if key not in sigs:
                sigs[key] = val
                new_count += 1
        binary_sig_count += new_count
        print(f"{len(bin_sigs)} cikarildi, {new_count} yeni")

    print(f"  -> Binary'lerden toplam {binary_sig_count} yeni signature")

    # Adim 3: Cikti dosyasini yaz
    print(f"\n[3/3] Cikti yaziliyor: {output_path}")

    output = OrderedDict()
    output["meta"] = {
        "generator": "karadul-sig-gen-rust",
        "date": datetime.now().strftime("%Y-%m-%d"),
        "version": "2.0",
        "total_signatures": len(sigs) - 1,  # meta haric
        "sources": {
            "pattern_generated": "Rust v0 + legacy mangling patterns for stdlib + popular crates",
            "binary_extracted": [b[1] for b in binaries],
        },
    }
    output["signatures"] = OrderedDict()

    # Kategoriye gore sirala
    sorted_sigs = sorted(sigs.items(), key=lambda x: (x[1].get("category", ""), x[0]))
    for key, val in sorted_sigs:
        output["signatures"][key] = val

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Istatistikler
    from collections import Counter
    cats = Counter(v.get("category", "?") for v in sigs.values())
    print(f"\n{'='*60}")
    print(f"TOPLAM: {len(sigs)} Rust signature")
    print(f"\nKategori dagilimi:")
    for cat, cnt in cats.most_common():
        print(f"  {cat}: {cnt}")
    print(f"\nCikti: {output_path}")
    print(f"Dosya boyutu: {os.path.getsize(output_path) / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()
