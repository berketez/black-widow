"""Event/utils category signatures — sig_db v1.13 Dalga 2 migration (ADR 0007 A9).

Kaynak: karadul/analyzers/signature_db.py icindeki 9 inline dict bu modulde
toplandi. Tip A "yumusak override" pattern'i (Faz 9 logging pilotu ile ozdes):
signature_db.py'de orijinal dict gövdeleri DOKUNULMADI; entegrasyon turunde
``from sigdb_builtin.event_utils import SIGNATURES`` ile bind edilecek.
A-DELETE asamasinda inline literal'ler silinip dogrudan import'a gecilir.

Migrasyon haritasi (signature_db.py icindeki orijinal isim -> bu modul anahtari):
  ``_LIBUV_SIGNATURES``      (69) -> ``libuv_signatures``
  ``_LIBEVENT_SIGNATURES``   (29) -> ``libevent_signatures``
  ``_REGEX_SIGNATURES``      (18) -> ``regex_signatures``
  ``_ICU_SIGNATURES``        (41) -> ``icu_signatures``
  ``_MATH_SIGNATURES``       (77) -> ``math_signatures``
  ``_QT_SIGNATURES``         (16) -> ``qt_signatures``
  ``_TESTING_SIGNATURES``    ( 9) -> ``testing_signatures``
  ``_MISC_SIGNATURES``       (44) -> ``misc_signatures``
  ``_MSGQUEUE_SIGNATURES``   (61) -> ``msgqueue_signatures``

Toplam: 364 imza.

NOT: ``misc_signatures`` icindeki ``_g_main_loop_*`` entry'leri tarihsel olarak
``category="event_loop"`` ile etiketlidir (GLib main loop). Ayni dict'te
"misc" ile birlikte kalmasi orijinal yapinin korunmasi icin bilinclidir;
yeniden kategorize etme islemi A-DELETE/rafinaj kapsami disindadir.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# libuv (event loop, async I/O, threading) — 69 entry
# Kaynak: signature_db.py _LIBUV_SIGNATURES.
# ---------------------------------------------------------------------------
_LIBUV_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Event loop
    "_uv_loop_init": {"lib": "libuv", "purpose": "Initialize event loop", "category": "event_loop"},
    "_uv_loop_close": {"lib": "libuv", "purpose": "Close event loop", "category": "event_loop"},
    "_uv_run": {"lib": "libuv", "purpose": "Run the event loop", "category": "event_loop"},
    "_uv_stop": {"lib": "libuv", "purpose": "Stop the event loop", "category": "event_loop"},
    "_uv_default_loop": {"lib": "libuv", "purpose": "Get default event loop", "category": "event_loop"},
    # TCP
    "_uv_tcp_init": {"lib": "libuv", "purpose": "Initialize TCP handle", "category": "network"},
    "_uv_tcp_bind": {"lib": "libuv", "purpose": "Bind TCP handle to address", "category": "network"},
    "_uv_tcp_connect": {"lib": "libuv", "purpose": "Establish TCP connection", "category": "network"},
    "_uv_listen": {"lib": "libuv", "purpose": "Start listening for connections", "category": "network"},
    "_uv_accept": {"lib": "libuv", "purpose": "Accept incoming connection", "category": "network"},
    # UDP
    "_uv_udp_init": {"lib": "libuv", "purpose": "Initialize UDP handle", "category": "network"},
    "_uv_udp_bind": {"lib": "libuv", "purpose": "Bind UDP handle to address", "category": "network"},
    "_uv_udp_send": {"lib": "libuv", "purpose": "Send UDP datagram", "category": "network"},
    "_uv_udp_recv_start": {"lib": "libuv", "purpose": "Start receiving UDP datagrams", "category": "network"},
    "_uv_udp_recv_stop": {"lib": "libuv", "purpose": "Stop receiving UDP datagrams", "category": "network"},
    # Stream I/O
    "_uv_read_start": {"lib": "libuv", "purpose": "Start reading from stream", "category": "io"},
    "_uv_read_stop": {"lib": "libuv", "purpose": "Stop reading from stream", "category": "io"},
    "_uv_write": {"lib": "libuv", "purpose": "Write data to stream", "category": "io"},
    "_uv_shutdown": {"lib": "libuv", "purpose": "Shutdown write side of stream", "category": "io"},
    # Handle lifecycle
    "_uv_close": {"lib": "libuv", "purpose": "Close handle", "category": "event_loop"},
    "_uv_is_active": {"lib": "libuv", "purpose": "Check if handle is active", "category": "event_loop"},
    "_uv_is_closing": {"lib": "libuv", "purpose": "Check if handle is closing", "category": "event_loop"},
    "_uv_ref": {"lib": "libuv", "purpose": "Reference handle (keeps loop alive)", "category": "event_loop"},
    "_uv_unref": {"lib": "libuv", "purpose": "Unreference handle", "category": "event_loop"},
    # Timer
    "_uv_timer_init": {"lib": "libuv", "purpose": "Initialize timer handle", "category": "event_loop"},
    "_uv_timer_start": {"lib": "libuv", "purpose": "Start timer", "category": "event_loop"},
    "_uv_timer_stop": {"lib": "libuv", "purpose": "Stop timer", "category": "event_loop"},
    "_uv_timer_again": {"lib": "libuv", "purpose": "Restart timer with repeat value", "category": "event_loop"},
    # Idle
    "_uv_idle_init": {"lib": "libuv", "purpose": "Initialize idle handle", "category": "event_loop"},
    "_uv_idle_start": {"lib": "libuv", "purpose": "Start idle handle", "category": "event_loop"},
    "_uv_idle_stop": {"lib": "libuv", "purpose": "Stop idle handle", "category": "event_loop"},
    # Async
    "_uv_async_init": {"lib": "libuv", "purpose": "Initialize async handle for cross-thread signaling", "category": "threading"},
    "_uv_async_send": {"lib": "libuv", "purpose": "Send async notification", "category": "threading"},
    # Signal
    "_uv_signal_init": {"lib": "libuv", "purpose": "Initialize signal handle", "category": "event_loop"},
    "_uv_signal_start": {"lib": "libuv", "purpose": "Start watching for signal", "category": "event_loop"},
    "_uv_signal_stop": {"lib": "libuv", "purpose": "Stop watching for signal", "category": "event_loop"},
    # Filesystem
    "_uv_fs_open": {"lib": "libuv", "purpose": "Async file open", "category": "io"},
    "_uv_fs_close": {"lib": "libuv", "purpose": "Async file close", "category": "io"},
    "_uv_fs_read": {"lib": "libuv", "purpose": "Async file read", "category": "io"},
    "_uv_fs_write": {"lib": "libuv", "purpose": "Async file write", "category": "io"},
    "_uv_fs_stat": {"lib": "libuv", "purpose": "Async file stat", "category": "io"},
    "_uv_fs_unlink": {"lib": "libuv", "purpose": "Async file delete", "category": "io"},
    "_uv_fs_mkdir": {"lib": "libuv", "purpose": "Async create directory", "category": "io"},
    "_uv_fs_scandir": {"lib": "libuv", "purpose": "Async directory scan", "category": "io"},
    # Pipe
    "_uv_pipe_init": {"lib": "libuv", "purpose": "Initialize pipe handle", "category": "io"},
    "_uv_pipe_open": {"lib": "libuv", "purpose": "Open existing fd as pipe", "category": "io"},
    "_uv_pipe_bind": {"lib": "libuv", "purpose": "Bind pipe to name", "category": "io"},
    "_uv_pipe_connect": {"lib": "libuv", "purpose": "Connect pipe to name", "category": "io"},
    # Process
    "_uv_spawn": {"lib": "libuv", "purpose": "Spawn child process", "category": "process"},
    "_uv_process_kill": {"lib": "libuv", "purpose": "Send signal to child process", "category": "process"},
    # Threading
    "_uv_thread_create": {"lib": "libuv", "purpose": "Create thread", "category": "threading"},
    "_uv_thread_join": {"lib": "libuv", "purpose": "Join thread", "category": "threading"},
    "_uv_mutex_init": {"lib": "libuv", "purpose": "Initialize mutex", "category": "threading"},
    "_uv_mutex_lock": {"lib": "libuv", "purpose": "Lock mutex", "category": "threading"},
    "_uv_mutex_unlock": {"lib": "libuv", "purpose": "Unlock mutex", "category": "threading"},
    "_uv_mutex_destroy": {"lib": "libuv", "purpose": "Destroy mutex", "category": "threading"},
    "_uv_rwlock_init": {"lib": "libuv", "purpose": "Initialize read-write lock", "category": "threading"},
    "_uv_rwlock_rdlock": {"lib": "libuv", "purpose": "Acquire read lock", "category": "threading"},
    "_uv_rwlock_wrlock": {"lib": "libuv", "purpose": "Acquire write lock", "category": "threading"},
    "_uv_rwlock_rdunlock": {"lib": "libuv", "purpose": "Release read lock", "category": "threading"},
    "_uv_rwlock_wrunlock": {"lib": "libuv", "purpose": "Release write lock", "category": "threading"},
    # DNS / address
    "_uv_getaddrinfo": {"lib": "libuv", "purpose": "Async DNS resolution (getaddrinfo)", "category": "network"},
    "_uv_freeaddrinfo": {"lib": "libuv", "purpose": "Free addrinfo result", "category": "network"},
    "_uv_ip4_addr": {"lib": "libuv", "purpose": "Convert IPv4 string to sockaddr", "category": "network"},
    "_uv_ip6_addr": {"lib": "libuv", "purpose": "Convert IPv6 string to sockaddr", "category": "network"},
    # Utility
    "_uv_strerror": {"lib": "libuv", "purpose": "Get error string", "category": "event_loop"},
    "_uv_err_name": {"lib": "libuv", "purpose": "Get error name constant", "category": "event_loop"},
    "_uv_version": {"lib": "libuv", "purpose": "Get libuv version number", "category": "event_loop"},
    "_uv_version_string": {"lib": "libuv", "purpose": "Get libuv version string", "category": "event_loop"},
}


# ---------------------------------------------------------------------------
# libevent (event-driven I/O, evbuffer, evhttp) — 29 entry
# Kaynak: signature_db.py _LIBEVENT_SIGNATURES.
# ---------------------------------------------------------------------------
_LIBEVENT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_event_base_new": {"lib": "libevent", "purpose": "Create new event base", "category": "event_loop"},
    "_event_base_free": {"lib": "libevent", "purpose": "Free event base", "category": "event_loop"},
    "_event_base_dispatch": {"lib": "libevent", "purpose": "Dispatch events (blocking)", "category": "event_loop"},
    "_event_base_loop": {"lib": "libevent", "purpose": "Run event loop with flags", "category": "event_loop"},
    "_event_base_loopbreak": {"lib": "libevent", "purpose": "Break out of event loop", "category": "event_loop"},
    "_event_base_loopexit": {"lib": "libevent", "purpose": "Schedule event loop exit", "category": "event_loop"},
    "_event_new": {"lib": "libevent", "purpose": "Create new event", "category": "event_loop"},
    "_event_free": {"lib": "libevent", "purpose": "Free event", "category": "event_loop"},
    "_event_add": {"lib": "libevent", "purpose": "Add event to pending set", "category": "event_loop"},
    "_event_del": {"lib": "libevent", "purpose": "Remove event from pending set", "category": "event_loop"},
    "_event_assign": {"lib": "libevent", "purpose": "Assign event fields (no alloc)", "category": "event_loop"},
    "_evbuffer_new": {"lib": "libevent", "purpose": "Create new evbuffer", "category": "io"},
    "_evbuffer_free": {"lib": "libevent", "purpose": "Free evbuffer", "category": "io"},
    "_evbuffer_add": {"lib": "libevent", "purpose": "Append data to evbuffer", "category": "io"},
    "_evbuffer_remove": {"lib": "libevent", "purpose": "Remove data from evbuffer", "category": "io"},
    "_evbuffer_get_length": {"lib": "libevent", "purpose": "Get evbuffer data length", "category": "io"},
    "_evbuffer_readln": {"lib": "libevent", "purpose": "Read line from evbuffer", "category": "io"},
    "_bufferevent_socket_new": {"lib": "libevent", "purpose": "Create socket-based bufferevent", "category": "network"},
    "_bufferevent_free": {"lib": "libevent", "purpose": "Free bufferevent", "category": "network"},
    "_bufferevent_setcb": {"lib": "libevent", "purpose": "Set bufferevent callbacks", "category": "network"},
    "_bufferevent_enable": {"lib": "libevent", "purpose": "Enable bufferevent reading/writing", "category": "network"},
    "_bufferevent_disable": {"lib": "libevent", "purpose": "Disable bufferevent reading/writing", "category": "network"},
    "_evconnlistener_new_bind": {"lib": "libevent", "purpose": "Create listener, bind and listen", "category": "network"},
    "_evconnlistener_free": {"lib": "libevent", "purpose": "Free connection listener", "category": "network"},
    "_evconnlistener_set_cb": {"lib": "libevent", "purpose": "Set listener accept callback", "category": "network"},
    "_evhttp_new": {"lib": "libevent", "purpose": "Create HTTP server", "category": "network"},
    "_evhttp_bind_socket": {"lib": "libevent", "purpose": "Bind HTTP server to port", "category": "network"},
    "_evhttp_set_cb": {"lib": "libevent", "purpose": "Set HTTP request handler", "category": "network"},
    "_evhttp_send_reply": {"lib": "libevent", "purpose": "Send HTTP response", "category": "network"},
}


# ---------------------------------------------------------------------------
# Regex (PCRE2, POSIX regex, RE2) — 18 entry
# Kaynak: signature_db.py _REGEX_SIGNATURES.
# ---------------------------------------------------------------------------
_REGEX_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_pcre2_compile_8": {"lib": "pcre2", "purpose": "Compile regex pattern (8-bit)", "category": "regex"},
    "_pcre2_match_8": {"lib": "pcre2", "purpose": "Match compiled regex (8-bit)", "category": "regex"},
    "_pcre2_match_data_create_from_pattern_8": {"lib": "pcre2", "purpose": "Create match data block from pattern", "category": "regex"},
    "_pcre2_get_ovector_pointer_8": {"lib": "pcre2", "purpose": "Get output vector pointer", "category": "regex"},
    "_pcre2_get_ovector_count_8": {"lib": "pcre2", "purpose": "Get output vector pair count", "category": "regex"},
    "_pcre2_code_free_8": {"lib": "pcre2", "purpose": "Free compiled regex", "category": "regex"},
    "_pcre2_match_data_free_8": {"lib": "pcre2", "purpose": "Free match data block", "category": "regex"},
    "_pcre2_pattern_info_8": {"lib": "pcre2", "purpose": "Query pattern information", "category": "regex"},
    "_pcre2_jit_compile_8": {"lib": "pcre2", "purpose": "JIT compile regex for speed", "category": "regex"},
    "_pcre2_jit_match_8": {"lib": "pcre2", "purpose": "Match using JIT-compiled regex", "category": "regex"},
    "_pcre2_substitute_8": {"lib": "pcre2", "purpose": "Search and replace with regex", "category": "regex"},
    "_regcomp": {"lib": "libc", "purpose": "Compile POSIX regular expression", "category": "regex"},
    "_regexec": {"lib": "libc", "purpose": "Execute POSIX regular expression", "category": "regex"},
    "_regfree": {"lib": "libc", "purpose": "Free compiled POSIX regex", "category": "regex"},
    "_regerror": {"lib": "libc", "purpose": "Get regex error message", "category": "regex"},
    "__ZN3re22RE2C1": {"lib": "re2", "purpose": "RE2 regex constructor (C++ mangled prefix)", "category": "regex"},
    "__ZN3re22RE211FullMatchN": {"lib": "re2", "purpose": "RE2::FullMatchN (C++ mangled prefix)", "category": "regex"},
    "__ZN3re22RE214PartialMatchN": {"lib": "re2", "purpose": "RE2::PartialMatchN (C++ mangled prefix)", "category": "regex"},
}


# ---------------------------------------------------------------------------
# ICU (International Components for Unicode) — 41 entry
# Kaynak: signature_db.py _ICU_SIGNATURES.
# ---------------------------------------------------------------------------
_ICU_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_u_init": {"lib": "icu", "purpose": "Initialize ICU library", "category": "unicode"},
    "_u_cleanup": {"lib": "icu", "purpose": "Clean up ICU library resources", "category": "unicode"},
    "_u_errorName": {"lib": "icu", "purpose": "Get ICU error code name", "category": "unicode"},
    "_ucnv_open": {"lib": "icu", "purpose": "Open charset converter", "category": "unicode"},
    "_ucnv_close": {"lib": "icu", "purpose": "Close charset converter", "category": "unicode"},
    "_ucnv_convert": {"lib": "icu", "purpose": "Convert between charsets", "category": "unicode"},
    "_ucnv_fromUChars": {"lib": "icu", "purpose": "Convert UChars to charset", "category": "unicode"},
    "_ucnv_toUChars": {"lib": "icu", "purpose": "Convert charset to UChars", "category": "unicode"},
    "_ubrk_open": {"lib": "icu", "purpose": "Open break iterator", "category": "unicode"},
    "_ubrk_close": {"lib": "icu", "purpose": "Close break iterator", "category": "unicode"},
    "_ubrk_next": {"lib": "icu", "purpose": "Move to next boundary", "category": "unicode"},
    "_ubrk_previous": {"lib": "icu", "purpose": "Move to previous boundary", "category": "unicode"},
    "_ubrk_first": {"lib": "icu", "purpose": "Move to first boundary", "category": "unicode"},
    "_ubrk_last": {"lib": "icu", "purpose": "Move to last boundary", "category": "unicode"},
    "_ucol_open": {"lib": "icu", "purpose": "Open collator for locale", "category": "unicode"},
    "_ucol_close": {"lib": "icu", "purpose": "Close collator", "category": "unicode"},
    "_ucol_strcoll": {"lib": "icu", "purpose": "Compare strings with collation", "category": "unicode"},
    "_ucol_getSortKey": {"lib": "icu", "purpose": "Get sort key for string", "category": "unicode"},
    "_unorm2_getNFCInstance": {"lib": "icu", "purpose": "Get NFC normalizer singleton", "category": "unicode"},
    "_unorm2_getNFDInstance": {"lib": "icu", "purpose": "Get NFD normalizer singleton", "category": "unicode"},
    "_unorm2_normalize": {"lib": "icu", "purpose": "Normalize Unicode string", "category": "unicode"},
    "_unorm2_isNormalized": {"lib": "icu", "purpose": "Check if string is normalized", "category": "unicode"},
    "_uregex_open": {"lib": "icu", "purpose": "Compile ICU regex pattern", "category": "unicode"},
    "_uregex_close": {"lib": "icu", "purpose": "Close ICU regex", "category": "unicode"},
    "_uregex_find": {"lib": "icu", "purpose": "Find next regex match", "category": "unicode"},
    "_uregex_group": {"lib": "icu", "purpose": "Get regex match group", "category": "unicode"},
    "_uidna_openUTS46": {"lib": "icu", "purpose": "Open IDNA UTS#46 processor", "category": "unicode"},
    "_uidna_close": {"lib": "icu", "purpose": "Close IDNA processor", "category": "unicode"},
    "_uidna_nameToASCII": {"lib": "icu", "purpose": "Convert domain name to ASCII (punycode)", "category": "unicode"},
    "_uloc_getDefault": {"lib": "icu", "purpose": "Get default locale", "category": "unicode"},
    "_uloc_setDefault": {"lib": "icu", "purpose": "Set default locale", "category": "unicode"},
    "_uloc_getLanguage": {"lib": "icu", "purpose": "Get language from locale", "category": "unicode"},
    "_uloc_getCountry": {"lib": "icu", "purpose": "Get country from locale", "category": "unicode"},
    "_udat_open": {"lib": "icu", "purpose": "Open date/time formatter", "category": "unicode"},
    "_udat_close": {"lib": "icu", "purpose": "Close date/time formatter", "category": "unicode"},
    "_udat_format": {"lib": "icu", "purpose": "Format date/time to string", "category": "unicode"},
    "_udat_parse": {"lib": "icu", "purpose": "Parse date/time from string", "category": "unicode"},
    "_unum_open": {"lib": "icu", "purpose": "Open number formatter", "category": "unicode"},
    "_unum_close": {"lib": "icu", "purpose": "Close number formatter", "category": "unicode"},
    "_unum_formatDouble": {"lib": "icu", "purpose": "Format double to string", "category": "unicode"},
    "_unum_parseDouble": {"lib": "icu", "purpose": "Parse double from string", "category": "unicode"},
}


# ---------------------------------------------------------------------------
# Math/BLAS/LAPACK/Apple Accelerate — 77 entry
# Kaynak: signature_db.py _MATH_SIGNATURES.
# ---------------------------------------------------------------------------
_MATH_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # C math (libm) - trigonometric
    "_sin": {"lib": "libm", "purpose": "Sine", "category": "math"},
    "_cos": {"lib": "libm", "purpose": "Cosine", "category": "math"},
    "_tan": {"lib": "libm", "purpose": "Tangent", "category": "math"},
    "_asin": {"lib": "libm", "purpose": "Arc sine", "category": "math"},
    "_acos": {"lib": "libm", "purpose": "Arc cosine", "category": "math"},
    "_atan": {"lib": "libm", "purpose": "Arc tangent", "category": "math"},
    "_atan2": {"lib": "libm", "purpose": "Arc tangent of y/x (two-argument)", "category": "math"},
    "_sinh": {"lib": "libm", "purpose": "Hyperbolic sine", "category": "math"},
    "_cosh": {"lib": "libm", "purpose": "Hyperbolic cosine", "category": "math"},
    "_tanh": {"lib": "libm", "purpose": "Hyperbolic tangent", "category": "math"},
    "_asinh": {"lib": "libm", "purpose": "Inverse hyperbolic sine", "category": "math"},
    "_acosh": {"lib": "libm", "purpose": "Inverse hyperbolic cosine", "category": "math"},
    "_atanh": {"lib": "libm", "purpose": "Inverse hyperbolic tangent", "category": "math"},
    "_exp": {"lib": "libm", "purpose": "Exponential (e^x)", "category": "math"},
    "_exp2": {"lib": "libm", "purpose": "Base-2 exponential (2^x)", "category": "math"},
    "_log": {"lib": "libm", "purpose": "Natural logarithm", "category": "math"},
    "_log2": {"lib": "libm", "purpose": "Base-2 logarithm", "category": "math"},
    "_log10": {"lib": "libm", "purpose": "Base-10 logarithm", "category": "math"},
    "_pow": {"lib": "libm", "purpose": "Power (x^y)", "category": "math"},
    "_sqrt": {"lib": "libm", "purpose": "Square root", "category": "math"},
    "_cbrt": {"lib": "libm", "purpose": "Cube root", "category": "math"},
    "_ceil": {"lib": "libm", "purpose": "Round up to integer", "category": "math"},
    "_floor": {"lib": "libm", "purpose": "Round down to integer", "category": "math"},
    "_round": {"lib": "libm", "purpose": "Round to nearest integer", "category": "math"},
    "_trunc": {"lib": "libm", "purpose": "Truncate toward zero", "category": "math"},
    "_fabs": {"lib": "libm", "purpose": "Absolute value (float)", "category": "math"},
    "_fmod": {"lib": "libm", "purpose": "Floating-point remainder", "category": "math"},
    "_remainder": {"lib": "libm", "purpose": "IEEE remainder", "category": "math"},
    "_fma": {"lib": "libm", "purpose": "Fused multiply-add (a*b+c)", "category": "math"},
    "_hypot": {"lib": "libm", "purpose": "Hypotenuse (sqrt(x^2+y^2))", "category": "math"},
    "_ldexp": {"lib": "libm", "purpose": "Load exponent (x * 2^n)", "category": "math"},
    "_frexp": {"lib": "libm", "purpose": "Extract significand and exponent", "category": "math"},
    "_modf": {"lib": "libm", "purpose": "Split into integer and fractional parts", "category": "math"},
    "_copysign": {"lib": "libm", "purpose": "Copy sign of number", "category": "math"},
    "_nextafter": {"lib": "libm", "purpose": "Next representable float toward y", "category": "math"},
    "_isnan": {"lib": "libm", "purpose": "Check for NaN", "category": "math"},
    "_isinf": {"lib": "libm", "purpose": "Check for infinity", "category": "math"},
    "_isfinite": {"lib": "libm", "purpose": "Check for finite value", "category": "math"},
    "_isnormal": {"lib": "libm", "purpose": "Check for normal (non-zero, non-denorm)", "category": "math"},
    # BLAS
    "_cblas_sgemm": {"lib": "blas", "purpose": "Single-precision general matrix multiply", "category": "math"},
    "_cblas_dgemm": {"lib": "blas", "purpose": "Double-precision general matrix multiply", "category": "math"},
    "_cblas_sgemv": {"lib": "blas", "purpose": "Single-precision matrix-vector multiply", "category": "math"},
    "_cblas_dgemv": {"lib": "blas", "purpose": "Double-precision matrix-vector multiply", "category": "math"},
    "_cblas_saxpy": {"lib": "blas", "purpose": "Single-precision y += a*x (AXPY)", "category": "math"},
    "_cblas_daxpy": {"lib": "blas", "purpose": "Double-precision y += a*x (AXPY)", "category": "math"},
    "_cblas_sdot": {"lib": "blas", "purpose": "Single-precision dot product", "category": "math"},
    "_cblas_ddot": {"lib": "blas", "purpose": "Double-precision dot product", "category": "math"},
    "_cblas_scopy": {"lib": "blas", "purpose": "Single-precision vector copy", "category": "math"},
    "_cblas_dcopy": {"lib": "blas", "purpose": "Double-precision vector copy", "category": "math"},
    "_cblas_sscal": {"lib": "blas", "purpose": "Single-precision vector scale", "category": "math"},
    "_cblas_dscal": {"lib": "blas", "purpose": "Double-precision vector scale", "category": "math"},
    "_cblas_snrm2": {"lib": "blas", "purpose": "Single-precision Euclidean norm", "category": "math"},
    "_cblas_dnrm2": {"lib": "blas", "purpose": "Double-precision Euclidean norm", "category": "math"},
    "_cblas_sasum": {"lib": "blas", "purpose": "Single-precision sum of absolute values", "category": "math"},
    "_cblas_dasum": {"lib": "blas", "purpose": "Double-precision sum of absolute values", "category": "math"},
    # LAPACK
    "_sgesv_": {"lib": "lapack", "purpose": "Solve linear system Ax=B (single)", "category": "math"},
    "_dgesv_": {"lib": "lapack", "purpose": "Solve linear system Ax=B (double)", "category": "math"},
    "_sgetrf_": {"lib": "lapack", "purpose": "LU factorization (single)", "category": "math"},
    "_dgetrf_": {"lib": "lapack", "purpose": "LU factorization (double)", "category": "math"},
    "_sgetri_": {"lib": "lapack", "purpose": "Matrix inverse from LU (single)", "category": "math"},
    "_dgetri_": {"lib": "lapack", "purpose": "Matrix inverse from LU (double)", "category": "math"},
    "_ssyev_": {"lib": "lapack", "purpose": "Symmetric eigenvalue decomposition (single)", "category": "math"},
    "_dsyev_": {"lib": "lapack", "purpose": "Symmetric eigenvalue decomposition (double)", "category": "math"},
    "_sgesvd_": {"lib": "lapack", "purpose": "SVD - singular value decomposition (single)", "category": "math"},
    "_dgesvd_": {"lib": "lapack", "purpose": "SVD - singular value decomposition (double)", "category": "math"},
    # Apple Accelerate / vDSP
    "_vDSP_vaddD": {"lib": "accelerate", "purpose": "Vector add (double)", "category": "math"},
    "_vDSP_vmulD": {"lib": "accelerate", "purpose": "Vector multiply (double)", "category": "math"},
    "_vDSP_fft_zripD": {"lib": "accelerate", "purpose": "In-place FFT (double, split complex)", "category": "math"},
    "_vDSP_create_fftsetupD": {"lib": "accelerate", "purpose": "Create FFT setup (double)", "category": "math"},
    "_vDSP_meanvD": {"lib": "accelerate", "purpose": "Vector mean (double)", "category": "math"},
    "_vDSP_maxvD": {"lib": "accelerate", "purpose": "Vector max (double)", "category": "math"},
    "_vDSP_minvD": {"lib": "accelerate", "purpose": "Vector min (double)", "category": "math"},
    "_vDSP_rmsqvD": {"lib": "accelerate", "purpose": "Vector root-mean-square (double)", "category": "math"},
    "_vImageConvert_ARGB8888toRGB888": {"lib": "accelerate", "purpose": "Convert ARGB8888 to RGB888 pixel format", "category": "math"},
    "_vImageScale_ARGB8888": {"lib": "accelerate", "purpose": "Scale/resize ARGB8888 image", "category": "math"},
    "_BNNSFilterCreateLayerFullyConnected": {"lib": "accelerate", "purpose": "Create BNNS fully connected neural layer", "category": "math"},
    "_BNNSFilterApply": {"lib": "accelerate", "purpose": "Apply BNNS neural network filter", "category": "math"},
}


# ---------------------------------------------------------------------------
# Qt Framework (C++ mangled names) — 16 entry
# Kaynak: signature_db.py _QT_SIGNATURES.
# ---------------------------------------------------------------------------
_QT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "__ZN7QObjectC1EPS_": {"lib": "qt", "purpose": "QObject::QObject(QObject* parent)", "category": "ui"},
    "__ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE": {"lib": "qt", "purpose": "QObject::connect (signal-slot)", "category": "ui"},
    "__ZN11QApplicationC1ERiPPci": {"lib": "qt", "purpose": "QApplication::QApplication(argc, argv)", "category": "ui"},
    "__ZN7QString8fromUtf8EPKci": {"lib": "qt", "purpose": "QString::fromUtf8(const char*, int)", "category": "ui"},
    "__ZN7QString6numberEi": {"lib": "qt", "purpose": "QString::number(int)", "category": "ui"},
    "__ZN5QFile4openE6QFlagsIN9QIODevice12OpenModeFlagEE": {"lib": "qt", "purpose": "QFile::open(OpenMode)", "category": "ui"},
    "__ZN12QTcpSocket": {"lib": "qt", "purpose": "QTcpSocket (partial mangled prefix)", "category": "network"},
    "__ZN8QProcess5startERK7QStringRK11QStringListE6QFlagsIN9QIODevice12OpenModeFlagEE": {"lib": "qt", "purpose": "QProcess::start(program, args, mode)", "category": "process"},
    "__ZN7QThread5startEN2Qt8PriorityE": {"lib": "qt", "purpose": "QThread::start(Priority)", "category": "threading"},
    "__ZN6QTimerC1EPN7QObject": {"lib": "qt", "purpose": "QTimer::QTimer(QObject* parent)", "category": "ui"},
    "__ZN8QVariantC1E": {"lib": "qt", "purpose": "QVariant constructor (partial mangled prefix)", "category": "ui"},
    "__ZN5QListI7QStringEC1Ev": {"lib": "qt", "purpose": "QList<QString>::QList()", "category": "ui"},
    "__ZN4QMapI7QString8QVariantEC1Ev": {"lib": "qt", "purpose": "QMap<QString,QVariant>::QMap()", "category": "ui"},
    "__ZN10QByteArrayC1EPKci": {"lib": "qt", "purpose": "QByteArray::QByteArray(const char*, int)", "category": "ui"},
    "__ZN5QJsonDocument8fromJsonERK10QByteArray": {"lib": "qt", "purpose": "QJsonDocument::fromJson(QByteArray) (partial)", "category": "ui"},
    "__ZN13QCoreApplication4execEv": {"lib": "qt", "purpose": "QCoreApplication::exec() - start event loop", "category": "ui"},
}


# ---------------------------------------------------------------------------
# Testing frameworks (gtest, catch2, cunit) — 9 entry
# Kaynak: signature_db.py _TESTING_SIGNATURES.
# ---------------------------------------------------------------------------
_TESTING_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "__ZN7testing4TestC1Ev": {"lib": "gtest", "purpose": "testing::Test constructor", "category": "testing"},
    "__ZN7testing8internal15AssertHelper": {"lib": "gtest", "purpose": "gtest ASSERT/EXPECT helper (partial mangled)", "category": "testing"},
    "__ZN7testing14InitGoogleTestEPiPPc": {"lib": "gtest", "purpose": "InitGoogleTest(argc, argv)", "category": "testing"},
    "__ZN5Catch10RunSession3runEv": {"lib": "catch2", "purpose": "Catch::Session::run() - run all tests", "category": "testing"},
    "_CU_initialize_registry": {"lib": "cunit", "purpose": "Initialize CUnit test registry", "category": "testing"},
    "_CU_add_suite": {"lib": "cunit", "purpose": "Add test suite to registry", "category": "testing"},
    "_CU_add_test": {"lib": "cunit", "purpose": "Add test case to suite", "category": "testing"},
    "_CU_basic_run_tests": {"lib": "cunit", "purpose": "Run all CUnit tests (basic)", "category": "testing"},
    "_CU_cleanup_registry": {"lib": "cunit", "purpose": "Clean up CUnit test registry", "category": "testing"},
}


# ---------------------------------------------------------------------------
# Misc (getopt, iconv, readline, termios, uuid, GLib) — 44 entry
# Kaynak: signature_db.py _MISC_SIGNATURES.
# ---------------------------------------------------------------------------
_MISC_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_getopt": {"lib": "libc", "purpose": "Parse command-line options", "category": "misc"},
    "_getopt_long": {"lib": "libc", "purpose": "Parse long command-line options", "category": "misc"},
    "_getopt_long_only": {"lib": "libc", "purpose": "Parse long options (single-dash allowed)", "category": "misc"},
    "_iconv_open": {"lib": "libc", "purpose": "Open charset conversion descriptor", "category": "misc"},
    "_iconv": {"lib": "libc", "purpose": "Convert character encoding", "category": "misc"},
    "_iconv_close": {"lib": "libc", "purpose": "Close charset conversion descriptor", "category": "misc"},
    "_readline": {"lib": "readline", "purpose": "Read line with editing/completion", "category": "misc"},
    "_add_history": {"lib": "readline", "purpose": "Add line to readline history", "category": "misc"},
    "_rl_bind_key": {"lib": "readline", "purpose": "Bind key to readline function", "category": "misc"},
    "_rl_completion_matches": {"lib": "readline", "purpose": "Generate completion matches", "category": "misc"},
    "_tcgetattr": {"lib": "libc", "purpose": "Get terminal attributes", "category": "misc"},
    "_tcsetattr": {"lib": "libc", "purpose": "Set terminal attributes", "category": "misc"},
    "_cfmakeraw": {"lib": "libc", "purpose": "Set terminal to raw mode", "category": "misc"},
    "_cfsetispeed": {"lib": "libc", "purpose": "Set terminal input baud rate", "category": "misc"},
    "_cfsetospeed": {"lib": "libc", "purpose": "Set terminal output baud rate", "category": "misc"},
    "_uuid_generate": {"lib": "libuuid", "purpose": "Generate UUID (v1 or v4)", "category": "misc"},
    "_uuid_generate_random": {"lib": "libuuid", "purpose": "Generate random UUID (v4)", "category": "misc"},
    "_uuid_generate_time": {"lib": "libuuid", "purpose": "Generate time-based UUID (v1)", "category": "misc"},
    "_uuid_parse": {"lib": "libuuid", "purpose": "Parse UUID string to binary", "category": "misc"},
    "_uuid_unparse": {"lib": "libuuid", "purpose": "Convert UUID binary to string", "category": "misc"},
    "_uuid_copy": {"lib": "libuuid", "purpose": "Copy UUID", "category": "misc"},
    "_uuid_compare": {"lib": "libuuid", "purpose": "Compare two UUIDs", "category": "misc"},
    "_uuid_clear": {"lib": "libuuid", "purpose": "Set UUID to null", "category": "misc"},
    "_g_malloc": {"lib": "glib", "purpose": "GLib memory allocate (aborts on fail)", "category": "misc"},
    "_g_free": {"lib": "glib", "purpose": "GLib memory free", "category": "misc"},
    "_g_realloc": {"lib": "glib", "purpose": "GLib memory reallocate", "category": "misc"},
    "_g_strdup": {"lib": "glib", "purpose": "GLib string duplicate", "category": "misc"},
    "_g_strsplit": {"lib": "glib", "purpose": "GLib split string by delimiter", "category": "misc"},
    "_g_strjoinv": {"lib": "glib", "purpose": "GLib join string array with separator", "category": "misc"},
    "_g_list_append": {"lib": "glib", "purpose": "Append to GList", "category": "misc"},
    "_g_list_remove": {"lib": "glib", "purpose": "Remove from GList", "category": "misc"},
    "_g_list_length": {"lib": "glib", "purpose": "Get GList length", "category": "misc"},
    "_g_list_free": {"lib": "glib", "purpose": "Free GList", "category": "misc"},
    "_g_hash_table_new": {"lib": "glib", "purpose": "Create GHashTable", "category": "misc"},
    "_g_hash_table_insert": {"lib": "glib", "purpose": "Insert into GHashTable", "category": "misc"},
    "_g_hash_table_lookup": {"lib": "glib", "purpose": "Lookup in GHashTable", "category": "misc"},
    "_g_hash_table_destroy": {"lib": "glib", "purpose": "Destroy GHashTable", "category": "misc"},
    "_g_main_loop_new": {"lib": "glib", "purpose": "Create GMainLoop", "category": "event_loop"},
    "_g_main_loop_run": {"lib": "glib", "purpose": "Run GMainLoop (blocking)", "category": "event_loop"},
    "_g_main_loop_quit": {"lib": "glib", "purpose": "Quit GMainLoop", "category": "event_loop"},
    "_g_signal_connect": {"lib": "glib", "purpose": "Connect signal to callback (GObject)", "category": "misc"},
    "_g_signal_emit": {"lib": "glib", "purpose": "Emit GObject signal", "category": "misc"},
    "_g_object_new": {"lib": "glib", "purpose": "Create new GObject instance", "category": "misc"},
    "_g_object_unref": {"lib": "glib", "purpose": "Decrement GObject reference count", "category": "misc"},
}


# ---------------------------------------------------------------------------
# Message queue / event systems (ZeroMQ, AMQP, Kafka, MQTT) — 61 entry
# Kaynak: signature_db.py _MSGQUEUE_SIGNATURES.
# ---------------------------------------------------------------------------
_MSGQUEUE_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- ZeroMQ ---
    "zmq_ctx_new": {"lib": "zeromq", "purpose": "create ZeroMQ context", "category": "messaging"},
    "zmq_ctx_destroy": {"lib": "zeromq", "purpose": "destroy ZeroMQ context", "category": "messaging"},
    "zmq_ctx_term": {"lib": "zeromq", "purpose": "terminate ZeroMQ context", "category": "messaging"},
    "zmq_socket": {"lib": "zeromq", "purpose": "create ZeroMQ socket", "category": "messaging"},
    "zmq_close": {"lib": "zeromq", "purpose": "close ZeroMQ socket", "category": "messaging"},
    "zmq_bind": {"lib": "zeromq", "purpose": "bind ZeroMQ socket to endpoint", "category": "messaging"},
    "zmq_connect": {"lib": "zeromq", "purpose": "connect ZeroMQ socket to endpoint", "category": "messaging"},
    "zmq_send": {"lib": "zeromq", "purpose": "send message on ZeroMQ socket", "category": "messaging"},
    "zmq_recv": {"lib": "zeromq", "purpose": "receive message from ZeroMQ socket", "category": "messaging"},
    "zmq_msg_init": {"lib": "zeromq", "purpose": "initialize ZeroMQ message", "category": "messaging"},
    "zmq_msg_init_size": {"lib": "zeromq", "purpose": "initialize message with size", "category": "messaging"},
    "zmq_msg_init_data": {"lib": "zeromq", "purpose": "initialize message with data", "category": "messaging"},
    "zmq_msg_send": {"lib": "zeromq", "purpose": "send multipart message", "category": "messaging"},
    "zmq_msg_recv": {"lib": "zeromq", "purpose": "receive multipart message", "category": "messaging"},
    "zmq_msg_close": {"lib": "zeromq", "purpose": "release message resources", "category": "messaging"},
    "zmq_msg_data": {"lib": "zeromq", "purpose": "get message data pointer", "category": "messaging"},
    "zmq_msg_size": {"lib": "zeromq", "purpose": "get message data size", "category": "messaging"},
    "zmq_setsockopt": {"lib": "zeromq", "purpose": "set ZeroMQ socket option", "category": "messaging"},
    "zmq_getsockopt": {"lib": "zeromq", "purpose": "get ZeroMQ socket option", "category": "messaging"},
    "zmq_poll": {"lib": "zeromq", "purpose": "poll ZeroMQ sockets for events", "category": "messaging"},
    "zmq_proxy": {"lib": "zeromq", "purpose": "start ZeroMQ proxy device", "category": "messaging"},

    # --- RabbitMQ / AMQP (rabbitmq-c) ---
    "amqp_new_connection": {"lib": "rabbitmq-c", "purpose": "create AMQP connection state", "category": "messaging"},
    "amqp_tcp_socket_new": {"lib": "rabbitmq-c", "purpose": "create TCP socket for AMQP", "category": "messaging"},
    "amqp_socket_open": {"lib": "rabbitmq-c", "purpose": "open AMQP socket connection", "category": "messaging"},
    "amqp_login": {"lib": "rabbitmq-c", "purpose": "AMQP login/authenticate", "category": "messaging"},
    "amqp_channel_open": {"lib": "rabbitmq-c", "purpose": "open AMQP channel", "category": "messaging"},
    "amqp_channel_close": {"lib": "rabbitmq-c", "purpose": "close AMQP channel", "category": "messaging"},
    "amqp_connection_close": {"lib": "rabbitmq-c", "purpose": "close AMQP connection", "category": "messaging"},
    "amqp_destroy_connection": {"lib": "rabbitmq-c", "purpose": "destroy AMQP connection", "category": "messaging"},
    "amqp_queue_declare": {"lib": "rabbitmq-c", "purpose": "declare AMQP queue", "category": "messaging"},
    "amqp_queue_bind": {"lib": "rabbitmq-c", "purpose": "bind queue to exchange", "category": "messaging"},
    "amqp_basic_publish": {"lib": "rabbitmq-c", "purpose": "publish message to exchange", "category": "messaging"},
    "amqp_basic_consume": {"lib": "rabbitmq-c", "purpose": "start consuming from queue", "category": "messaging"},
    "amqp_consume_message": {"lib": "rabbitmq-c", "purpose": "consume next message", "category": "messaging"},
    "amqp_basic_ack": {"lib": "rabbitmq-c", "purpose": "acknowledge message", "category": "messaging"},
    "amqp_exchange_declare": {"lib": "rabbitmq-c", "purpose": "declare AMQP exchange", "category": "messaging"},

    # --- librdkafka (Kafka) ---
    "rd_kafka_new": {"lib": "librdkafka", "purpose": "create Kafka handle (producer/consumer)", "category": "messaging"},
    "rd_kafka_destroy": {"lib": "librdkafka", "purpose": "destroy Kafka handle", "category": "messaging"},
    "rd_kafka_topic_new": {"lib": "librdkafka", "purpose": "create Kafka topic handle", "category": "messaging"},
    "rd_kafka_topic_destroy": {"lib": "librdkafka", "purpose": "destroy Kafka topic handle", "category": "messaging"},
    "rd_kafka_produce": {"lib": "librdkafka", "purpose": "produce message to Kafka topic", "category": "messaging"},
    "rd_kafka_poll": {"lib": "librdkafka", "purpose": "poll Kafka for events/callbacks", "category": "messaging"},
    "rd_kafka_flush": {"lib": "librdkafka", "purpose": "flush outstanding Kafka produce requests", "category": "messaging"},
    "rd_kafka_subscribe": {"lib": "librdkafka", "purpose": "subscribe to Kafka topics", "category": "messaging"},
    "rd_kafka_consumer_poll": {"lib": "librdkafka", "purpose": "poll Kafka consumer for messages", "category": "messaging"},
    "rd_kafka_consumer_close": {"lib": "librdkafka", "purpose": "close Kafka consumer", "category": "messaging"},
    "rd_kafka_message_destroy": {"lib": "librdkafka", "purpose": "destroy Kafka message", "category": "messaging"},
    "rd_kafka_conf_new": {"lib": "librdkafka", "purpose": "create Kafka configuration", "category": "messaging"},
    "rd_kafka_conf_set": {"lib": "librdkafka", "purpose": "set Kafka configuration property", "category": "messaging"},
    "rd_kafka_commit": {"lib": "librdkafka", "purpose": "commit Kafka consumer offsets", "category": "messaging"},
    "rd_kafka_offset_store": {"lib": "librdkafka", "purpose": "store Kafka offset for commit", "category": "messaging"},

    # --- Eclipse Paho MQTT ---
    "MQTTClient_create": {"lib": "paho-mqtt", "purpose": "create MQTT client", "category": "messaging"},
    "MQTTClient_connect": {"lib": "paho-mqtt", "purpose": "connect to MQTT broker", "category": "messaging"},
    "MQTTClient_disconnect": {"lib": "paho-mqtt", "purpose": "disconnect from MQTT broker", "category": "messaging"},
    "MQTTClient_destroy": {"lib": "paho-mqtt", "purpose": "destroy MQTT client", "category": "messaging"},
    "MQTTClient_publish": {"lib": "paho-mqtt", "purpose": "publish MQTT message", "category": "messaging"},
    "MQTTClient_subscribe": {"lib": "paho-mqtt", "purpose": "subscribe to MQTT topic", "category": "messaging"},
    "MQTTClient_unsubscribe": {"lib": "paho-mqtt", "purpose": "unsubscribe from MQTT topic", "category": "messaging"},
    "MQTTClient_receive": {"lib": "paho-mqtt", "purpose": "receive MQTT message", "category": "messaging"},
    "MQTTClient_setCallbacks": {"lib": "paho-mqtt", "purpose": "set MQTT callback functions", "category": "messaging"},
    "MQTTClient_yield": {"lib": "paho-mqtt", "purpose": "yield to MQTT client loop", "category": "messaging"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category('event_utils') bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur.
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "libuv_signatures": _LIBUV_SIGNATURES_DATA,
    "libevent_signatures": _LIBEVENT_SIGNATURES_DATA,
    "regex_signatures": _REGEX_SIGNATURES_DATA,
    "icu_signatures": _ICU_SIGNATURES_DATA,
    "math_signatures": _MATH_SIGNATURES_DATA,
    "qt_signatures": _QT_SIGNATURES_DATA,
    "testing_signatures": _TESTING_SIGNATURES_DATA,
    "misc_signatures": _MISC_SIGNATURES_DATA,
    "msgqueue_signatures": _MSGQUEUE_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
