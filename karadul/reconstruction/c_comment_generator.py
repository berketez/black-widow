"""Ghidra decompile ciktisina akilli yorumlar ekler.

Decompile edilmis C dosyalarini alir, fonksiyon metadata'si (functions.json),
string referanslari (strings.json), cagri grafigi (call_graph.json) ve
algoritma tespit sonuclariyla (c_algorithm_id) zenginlestirilmis yorumlar uretir.

Yorum tipleri:
1. Function Header Block -- Doxygen-benzeri fonksiyon baslik yorumu
2. System Call Annotations -- malloc, memcpy, open gibi bilinen cagrilara aciklama
3. Vulnerability Annotations -- strcpy, gets, sprintf gibi tehlikeli kullanima uyari
4. Control Flow Annotations -- state machine, infinite loop, switch/case aciklamasi
5. Algorithm Labels -- c_algorithm_id sonuclarindan algoritma etiketleri
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES, Config
from karadul.reconstruction.c_algorithm_id import AlgorithmMatch

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CCommentResult:
    """Yorum ekleme sonucu.

    Attributes:
        success: Islem basarili mi.
        output_files: Olusturulan cikti dosyalari.
        total_comments_added: Toplam eklenen yorum sayisi.
        function_headers: Eklenen fonksiyon baslik yorumu sayisi.
        syscall_annotations: Eklenen sistem cagri yorumu sayisi.
        vulnerability_warnings: Eklenen guvenlik uyarisi sayisi.
        algorithm_labels: Eklenen algoritma etiketi sayisi.
        control_flow_annotations: Eklenen kontrol akisi yorumu sayisi.
        logic_comments: Eklenen mantik/blok seviyesi yorum sayisi.
        computation_annotations: Eklenen Computation Recovery yorumu sayisi.
        errors: Hata mesajlari.
    """

    success: bool
    output_files: list[Path] = field(default_factory=list)
    total_comments_added: int = 0
    function_headers: int = 0
    syscall_annotations: int = 0
    vulnerability_warnings: int = 0
    algorithm_labels: int = 0
    control_flow_annotations: int = 0
    logic_comments: int = 0
    computation_annotations: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output_files": [str(p) for p in self.output_files],
            "total_comments_added": self.total_comments_added,
            "function_headers": self.function_headers,
            "syscall_annotations": self.syscall_annotations,
            "vulnerability_warnings": self.vulnerability_warnings,
            "algorithm_labels": self.algorithm_labels,
            "control_flow_annotations": self.control_flow_annotations,
            "logic_comments": self.logic_comments,
            "computation_annotations": self.computation_annotations,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Sistem cagrisi dokumantasyonu (100+ girdi)
# ---------------------------------------------------------------------------

SYSCALL_DOCS: dict[str, str] = {
    # Bellek yonetimi
    "malloc": "allocates {arg0} bytes on heap",
    "calloc": "allocates {arg0}*{arg1} zero-initialized bytes",
    "realloc": "resizes allocation to {arg1} bytes",
    "free": "releases heap allocation",
    "mmap": "maps {arg1} bytes of memory (prot={arg2})",
    "munmap": "unmaps {arg1} bytes of memory",
    "mprotect": "changes memory protection on {arg1} bytes (prot={arg2})",
    "mlock": "locks {arg1} bytes in physical memory",
    "munlock": "unlocks {arg1} bytes from physical memory",
    "brk": "adjusts program break (heap end)",
    "sbrk": "increments program break by {arg0} bytes",
    "posix_memalign": "allocates {arg2} bytes aligned to {arg1}",
    "valloc": "allocates {arg0} bytes page-aligned",
    # String islemleri
    "memcpy": "copies {arg2} bytes from src to dest",
    "memmove": "copies {arg2} bytes (overlap-safe)",
    "memset": "fills {arg2} bytes with value {arg1}",
    "memcmp": "compares {arg2} bytes of memory",
    "strcmp": "compares two strings, returns 0 if equal",
    "strncmp": "compares up to {arg2} chars of two strings",
    "strcpy": "copies string to dest (UNSAFE: no bounds check)",
    "strncpy": "copies up to {arg2} chars to dest",
    "strcat": "appends string to dest (UNSAFE: no bounds check)",
    "strncat": "appends up to {arg2} chars to dest",
    "strlen": "returns length of null-terminated string",
    "strnlen": "returns length of string, max {arg1}",
    "strchr": "finds first occurrence of char in string",
    "strrchr": "finds last occurrence of char in string",
    "strstr": "finds first occurrence of substring",
    "strtok": "tokenizes string by delimiters",
    "strtok_r": "tokenizes string (thread-safe)",
    "strdup": "duplicates string (malloc + strcpy)",
    "strndup": "duplicates up to {arg1} chars of string",
    "strerror": "returns error message string",
    "strtol": "converts string to long integer",
    "strtoul": "converts string to unsigned long",
    "strtod": "converts string to double",
    "atoi": "converts string to integer",
    "atol": "converts string to long",
    "atof": "converts string to float",
    # Dosya islemleri
    "open": "opens file descriptor",
    "close": "closes file descriptor",
    "read": "reads up to {arg2} bytes into buffer",
    "write": "writes {arg2} bytes from buffer",
    "lseek": "seeks to offset {arg1} in file",
    "fopen": "opens file stream",
    "fclose": "closes file stream",
    "fread": "reads {arg2}*{arg1} bytes from stream",
    "fwrite": "writes {arg2}*{arg1} bytes to stream",
    "fgets": "reads line from stream (max {arg1} chars)",
    "fputs": "writes string to stream",
    "fprintf": "formatted write to stream",
    "fscanf": "formatted read from stream",
    "fseek": "seeks in file stream",
    "ftell": "returns current position in stream",
    "rewind": "resets stream position to beginning",
    "fflush": "flushes stream buffer",
    "feof": "checks end-of-file indicator",
    "ferror": "checks stream error indicator",
    "fileno": "returns file descriptor from stream",
    "fdopen": "creates stream from file descriptor",
    "dup": "duplicates file descriptor",
    "dup2": "duplicates fd to specific number",
    "stat": "gets file status/metadata",
    "fstat": "gets file status from fd",
    "lstat": "gets symlink status",
    "access": "checks file permissions",
    "chmod": "changes file permissions",
    "chown": "changes file ownership",
    "unlink": "deletes file",
    "rename": "renames file",
    "mkdir": "creates directory",
    "rmdir": "removes empty directory",
    "opendir": "opens directory stream",
    "readdir": "reads next directory entry",
    "closedir": "closes directory stream",
    "truncate": "truncates file to {arg1} bytes",
    "ftruncate": "truncates fd to {arg1} bytes",
    "fsync": "synchronizes file to disk",
    "link": "creates hard link",
    "symlink": "creates symbolic link",
    "readlink": "reads symbolic link target",
    "realpath": "resolves to absolute path",
    "getcwd": "gets current working directory",
    "chdir": "changes working directory",
    # Ag islemleri
    "socket": "creates network socket (domain={arg0}, type={arg1})",
    "connect": "connects socket to remote address",
    "bind": "binds socket to local address",
    "listen": "marks socket as passive listener (backlog={arg1})",
    "accept": "accepts incoming connection",
    "send": "sends {arg2} bytes on connected socket",
    "recv": "receives up to {arg2} bytes from socket",
    "sendto": "sends {arg2} bytes to specified address",
    "recvfrom": "receives up to {arg3} bytes with source address",
    "sendmsg": "sends message on socket",
    "recvmsg": "receives message from socket",
    "setsockopt": "sets socket option",
    "getsockopt": "gets socket option",
    "shutdown": "shuts down socket (how={arg1})",
    "getaddrinfo": "resolves hostname to address",
    "freeaddrinfo": "frees address info",
    "gethostbyname": "resolves hostname (deprecated)",
    "gethostbyaddr": "reverse DNS lookup (deprecated)",
    "inet_pton": "converts address string to binary",
    "inet_ntop": "converts binary address to string",
    "htons": "converts short to network byte order",
    "htonl": "converts long to network byte order",
    "ntohs": "converts short from network byte order",
    "ntohl": "converts long from network byte order",
    "select": "monitors multiple fds for activity",
    "poll": "monitors multiple fds (poll-based)",
    "epoll_create": "creates epoll instance",
    "epoll_ctl": "modifies epoll interest list",
    "epoll_wait": "waits for epoll events",
    "kqueue": "creates kqueue instance (BSD/macOS)",
    "kevent": "registers/receives kqueue events",
    # Surec islemleri
    "fork": "creates child process",
    "vfork": "creates child process (shares memory)",
    "exec": "replaces process image",
    "execve": "replaces process image with args+env",
    "execvp": "replaces process (searches PATH)",
    "wait": "waits for child process",
    "waitpid": "waits for specific child process",
    "exit": "terminates process with status {arg0}",
    "_exit": "terminates process immediately",
    "abort": "terminates with SIGABRT",
    "kill": "sends signal {arg1} to process {arg0}",
    "raise": "sends signal to self",
    "signal": "sets signal handler",
    "sigaction": "sets signal handler (extended)",
    "getpid": "returns current process ID",
    "getppid": "returns parent process ID",
    "getuid": "returns user ID",
    "geteuid": "returns effective user ID",
    "setuid": "sets user ID",
    "seteuid": "sets effective user ID",
    "getgid": "returns group ID",
    "setgid": "sets group ID",
    # Thread islemleri
    "pthread_create": "creates new thread",
    "pthread_join": "waits for thread completion",
    "pthread_detach": "detaches thread",
    "pthread_exit": "terminates calling thread",
    "pthread_mutex_init": "initializes mutex",
    "pthread_mutex_lock": "locks mutex",
    "pthread_mutex_unlock": "unlocks mutex",
    "pthread_mutex_destroy": "destroys mutex",
    "pthread_cond_init": "initializes condition variable",
    "pthread_cond_wait": "waits on condition variable",
    "pthread_cond_signal": "signals condition variable",
    "pthread_cond_broadcast": "broadcasts condition variable",
    "pthread_rwlock_init": "initializes read-write lock",
    "pthread_rwlock_rdlock": "acquires read lock",
    "pthread_rwlock_wrlock": "acquires write lock",
    "pthread_rwlock_unlock": "unlocks read-write lock",
    # System
    "system": "executes shell command (DANGEROUS if input unsanitized)",
    "popen": "opens pipe to shell command",
    "pclose": "closes pipe",
    "getenv": "reads environment variable",
    "setenv": "sets environment variable",
    "unsetenv": "unsets environment variable",
    "ioctl": "device control operation",
    "fcntl": "file descriptor control",
    "ptrace": "process trace/debug control",
    "sysctl": "kernel parameter query",
    "dlopen": "loads dynamic library",
    "dlsym": "looks up symbol in dynamic library",
    "dlclose": "unloads dynamic library",
    "dlerror": "returns dynamic linker error",
    # I/O multiplexing / async
    "pipe": "creates pipe (fd pair)",
    "pipe2": "creates pipe with flags",
    "socketpair": "creates connected socket pair",
    "eventfd": "creates event file descriptor",
    "timerfd_create": "creates timer file descriptor",
    "signalfd": "creates signal file descriptor",
    # Time
    "time": "returns current time (seconds since epoch)",
    "gettimeofday": "returns current time (microseconds)",
    "clock_gettime": "returns high-resolution time",
    "sleep": "suspends for {arg0} seconds",
    "usleep": "suspends for {arg0} microseconds",
    "nanosleep": "suspends for specified nanoseconds",
    # Formatted I/O
    "printf": "formatted output to stdout",
    "sprintf": "formatted output to string (UNSAFE: no bounds check)",
    "snprintf": "formatted output to string (max {arg1} chars)",
    "sscanf": "formatted input from string",
    "vprintf": "formatted output (va_list)",
    "vsnprintf": "formatted output to string (va_list, bounded)",
    # Misc
    "qsort": "sorts array of {arg1} elements",
    "bsearch": "binary search in sorted array",
    "rand": "returns pseudo-random number",
    "srand": "seeds random number generator",
    "arc4random": "returns cryptographic random number",
    "arc4random_buf": "fills buffer with random bytes",
    "assert": "assertion check (aborts on failure)",
    "setjmp": "saves execution context",
    "longjmp": "restores execution context (non-local jump)",
    # Apple / macOS specific
    "dispatch_async": "submits block to GCD queue",
    "dispatch_sync": "submits block synchronously to GCD queue",
    "dispatch_queue_create": "creates GCD dispatch queue",
    "dispatch_semaphore_create": "creates GCD semaphore",
    "dispatch_semaphore_wait": "waits on GCD semaphore",
    "dispatch_semaphore_signal": "signals GCD semaphore",
    "objc_msgSend": "Objective-C message send",
    "objc_getClass": "looks up Objective-C class",
    "NSLog": "Objective-C formatted logging",
    "CFRelease": "releases Core Foundation object",
    "CFRetain": "retains Core Foundation object",
}


# ---------------------------------------------------------------------------
# Guvenlik uyari pattern'leri
# ---------------------------------------------------------------------------

VULN_PATTERNS: list[dict[str, str]] = [
    {
        "pattern": r"\bstrcpy\s*\(",
        "warning": "VULN: Buffer overflow - use strncpy or strlcpy instead",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bstrcat\s*\(",
        "warning": "VULN: Buffer overflow - use strncat or strlcat instead",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bsprintf\s*\(",
        "warning": "VULN: Format string / buffer overflow - use snprintf instead",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bgets\s*\(",
        "warning": "VULN: Unbounded read - use fgets instead (gets is removed in C11)",
        "severity": "CRITICAL",
    },
    {
        "pattern": r"\bscanf\s*\(\s*\"[^\"]*%s",
        "warning": "VULN: Unbounded string read - use width specifier (e.g. %255s)",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bsystem\s*\(",
        "warning": "VULN: Command injection risk if argument from user input",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bpopen\s*\(",
        "warning": "VULN: Command injection risk if argument from user input",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bexecvp?\s*\(",
        "warning": "WARNING: Process execution - verify arguments are sanitized",
        "severity": "MEDIUM",
    },
    {
        "pattern": r"\bfree\s*\([^)]+\).*\bfree\s*\(",
        "warning": "VULN: Possible double-free",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)",
        "warning": "VULN: Format string - use printf(\"%s\", var) instead",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bvsprintf\s*\(",
        "warning": "VULN: Unbounded formatted write - use vsnprintf instead",
        "severity": "HIGH",
    },
    {
        "pattern": r"\batoi\s*\(",
        "warning": "WARNING: No error checking - use strtol for robust parsing",
        "severity": "LOW",
    },
    {
        "pattern": r"\bstrtok\s*\(",
        "warning": "WARNING: Not thread-safe - use strtok_r in multi-threaded code",
        "severity": "LOW",
    },
    {
        "pattern": r"\bptrace\s*\(",
        "warning": "SECURITY: Process tracing / anti-debug mechanism",
        "severity": "MEDIUM",
    },
    {
        "pattern": r"\bmprotect\s*\(.*PROT_EXEC",
        "warning": "SECURITY: Making memory executable - possible code injection",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bmmap\s*\(.*PROT_EXEC",
        "warning": "SECURITY: Mapping executable memory",
        "severity": "MEDIUM",
    },
    {
        "pattern": r"\bsetuid\s*\(\s*0\s*\)",
        "warning": "SECURITY: Attempting to set UID to root",
        "severity": "HIGH",
    },
    {
        "pattern": r"\bchmod\s*\([^,]+,\s*0?777\s*\)",
        "warning": "SECURITY: Setting world-writable permissions",
        "severity": "MEDIUM",
    },
    {
        "pattern": r"open\s*\([^,]*(?:/etc/passwd|/etc/shadow)",
        "warning": "SECURITY: Accessing system password/shadow file",
        "severity": "HIGH",
    },
    {
        "pattern": r"\beval\s*\(|\bexecve?\s*\(",
        "warning": "WARNING: Dynamic code execution",
        "severity": "MEDIUM",
    },
    {
        "pattern": r"\bsignal\s*\(\s*SIG(?:SEGV|BUS|ILL)\s*,\s*SIG_IGN",
        "warning": "WARNING: Ignoring critical signal - may mask crashes",
        "severity": "MEDIUM",
    },
    {
        "pattern": r"\balloca\s*\(",
        "warning": "WARNING: Stack allocation - may cause stack overflow for large sizes",
        "severity": "MEDIUM",
    },
    {
        "pattern": r"\bmemcpy\s*\([^;]*\bstrlen\b",
        "warning": "WARNING: memcpy with strlen - check for off-by-one (null terminator)",
        "severity": "LOW",
    },
]

# Regex'leri onceden derle
_VULN_COMPILED: list[tuple[re.Pattern, str, str]] = [
    (re.compile(v["pattern"]), v["warning"], v["severity"])
    for v in VULN_PATTERNS
]


# ---------------------------------------------------------------------------
# Kontrol akisi pattern'leri
# ---------------------------------------------------------------------------

CONTROL_FLOW_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": re.compile(r"while\s*\(\s*(?:1|true|TRUE)\s*\)"),
        "comment": "Infinite loop - likely event/main loop",
    },
    {
        "pattern": re.compile(r"for\s*\(\s*;\s*;\s*\)"),
        "comment": "Infinite loop (for(;;)) - likely event/main loop",
    },
    {
        "pattern": re.compile(r"switch\s*\(\s*(\w+)\s*\)"),
        "comment_fn": lambda m, body: _describe_switch(m.group(1), body),
    },
    {
        "pattern": re.compile(r"goto\s+(\w+)"),
        "comment": "Uses goto - check for error cleanup pattern",
    },
    {
        "pattern": re.compile(r"if\s*\(\s*\w+\s*(?:==|!=)\s*NULL\s*\)"),
        "comment": "NULL pointer check",
    },
    {
        "pattern": re.compile(r"assert\s*\("),
        "comment": "Debug assertion - removed in release builds",
    },
    {
        "pattern": re.compile(
            r"(?:pthread_mutex_lock|dispatch_semaphore_wait|OSSpinLockLock)\s*\("
        ),
        "comment": "Synchronization point - thread safety",
    },
    {
        "pattern": re.compile(r"setjmp\s*\("),
        "comment": "Non-local jump setup - C exception handling mechanism",
    },
    {
        "pattern": re.compile(r"longjmp\s*\("),
        "comment": "Non-local jump - unwinding to setjmp point",
    },
]


def _describe_switch(var_name: str, body: str) -> str:
    """switch statement'in case sayisini sayarak aciklama uret."""
    case_count = len(re.findall(r"\bcase\s+", body))
    if case_count > 5:
        return f"State machine with {case_count} states on '{var_name}' - likely protocol/command handler"
    elif case_count > 0:
        return f"Switch on '{var_name}' with {case_count} cases"
    return f"Switch on '{var_name}'"


# ---------------------------------------------------------------------------
# Mantik/blok seviyesi yorum pattern'leri (Logic Comments)
# ---------------------------------------------------------------------------
# Bu pattern'ler decompile edilmis C kodundaki mantiksal bloklari tanir
# ve ne yaptiklarina dair kisa aciklama uretir.
# Oncelik: en spesifik pattern once kontrol edilir.

LOGIC_COMMENT_PATTERNS: list[dict[str, Any]] = [
    # ---- Error check: return on negative/failure ----
    {
        "pattern": re.compile(
            r"if\s*\(\s*(\w+)\s*<\s*0\s*\)\s*\{?"
        ),
        "comment_fn": lambda m, ctx: _logic_error_return(m, ctx),
        "category": "error_check",
    },
    # ---- Error check: return on nonzero (errno style) ----
    {
        "pattern": re.compile(
            r"if\s*\(\s*(\w+)\s*!=\s*0\s*\)\s*\{?"
        ),
        "comment_fn": lambda m, ctx: _logic_nonzero_check(m, ctx),
        "category": "error_check",
    },
    # ---- NULL pointer check (more specific than control flow) ----
    {
        "pattern": re.compile(
            r"if\s*\(\s*(\w+)\s*==\s*(?:NULL|0|0x0|\(\s*void\s*\*\s*\)\s*0)\s*\)"
        ),
        "comment_fn": lambda m, ctx: _logic_null_check(m, ctx),
        "category": "null_check",
    },
    # ---- NULL pointer check (negated form) ----
    {
        "pattern": re.compile(
            r"if\s*\(\s*(\w+)\s*!=\s*(?:NULL|0|0x0|\(\s*void\s*\*\s*\)\s*0)\s*\)"
        ),
        "comment": "non-null check: proceed if valid",
        "category": "null_check",
    },
    # ---- Bounds check ----
    {
        "pattern": re.compile(
            r"if\s*\(\s*(\w+)\s*(?:>=|>)\s*(\w+)\s*\)"
        ),
        "comment_fn": lambda m, ctx: _logic_bounds_check(m, ctx),
        "category": "bounds_check",
    },
    # ---- Counted for-loop ----
    {
        "pattern": re.compile(
            r"for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\s*;\s*\1\s*(?:\+\+|\+=\s*1)\s*\)"
        ),
        "comment_fn": lambda m, ctx: f"iterate over {_format_iter_bound(m.group(2))}",
        "category": "loop",
    },
    # ---- Counted for-loop (nonzero start) ----
    {
        "pattern": re.compile(
            r"for\s*\(\s*(\w+)\s*=\s*(\w+)\s*;\s*\1\s*<\s*(\w+)\s*;\s*\1\s*(?:\+\+|\+=\s*1)\s*\)"
        ),
        "comment_fn": lambda m, ctx: (
            f"iterate from {m.group(2)} to {m.group(3)}"
        ),
        "category": "loop",
    },
    # ---- Reverse for-loop (countdown) ----
    {
        "pattern": re.compile(
            r"for\s*\(\s*(\w+)\s*=\s*(\w+)\s*;\s*(?:\1\s*>=?\s*0|\1\s*!=\s*0)\s*;\s*\1\s*--\s*\)"
        ),
        "comment": "reverse iteration (countdown)",
        "category": "loop",
    },
    # ---- while-break loop ----
    {
        "pattern": re.compile(
            r"while\s*\(\s*(?:1|true|TRUE)\s*\)\s*\{"
        ),
        "comment_fn": lambda m, ctx: _logic_while_break(m, ctx),
        "category": "loop",
    },
    # ---- do-while loop ----
    {
        "pattern": re.compile(
            r"do\s*\{"
        ),
        "comment": "do-while: execute at least once",
        "category": "loop",
    },
    # ---- Memory allocation + null check combo ----
    {
        "pattern": re.compile(
            r"(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\("
        ),
        "comment_fn": lambda m, ctx: _logic_alloc_pattern(m, ctx),
        "category": "memory",
    },
    # ---- free() release ----
    {
        "pattern": re.compile(
            r"free\s*\(\s*(\w+)\s*\)\s*;"
        ),
        "comment_fn": lambda m, ctx: f"release {m.group(1)}",
        "category": "memory",
    },
    # ---- memcpy with readable args ----
    {
        "pattern": re.compile(
            r"memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)"
        ),
        "comment_fn": lambda m, ctx: (
            f"copy {_format_iter_bound(m.group(3))} bytes"
            f" from {m.group(2)} to {m.group(1)}"
        ),
        "category": "memory",
    },
    # ---- memset (zero-init pattern) ----
    {
        "pattern": re.compile(
            r"memset\s*\(\s*(\w+)\s*,\s*0\s*,\s*(\w+)\s*\)"
        ),
        "comment_fn": lambda m, ctx: (
            f"zero-initialize {_format_iter_bound(m.group(2))} bytes"
            f" of {m.group(1)}"
        ),
        "category": "memory",
    },
    # ---- strcmp comparison ----
    {
        "pattern": re.compile(
            r"strcmp\s*\(\s*(\w+)\s*,\s*([^)]+)\s*\)"
        ),
        "comment_fn": lambda m, ctx: _logic_strcmp(m, ctx),
        "category": "string_op",
    },
    # ---- strncmp comparison ----
    {
        "pattern": re.compile(
            r"strncmp\s*\(\s*(\w+)\s*,\s*([^,]+)\s*,\s*(\w+)\s*\)"
        ),
        "comment_fn": lambda m, ctx: (
            f"compare first {m.group(3)} chars of {m.group(1)}"
        ),
        "category": "string_op",
    },
    # ---- switch dispatch ----
    {
        "pattern": re.compile(
            r"switch\s*\(\s*(\w+)\s*\)\s*\{"
        ),
        "comment_fn": lambda m, ctx: f"dispatch on {m.group(1)}",
        "category": "dispatch",
    },
    # ---- Return value / early return ----
    {
        "pattern": re.compile(
            r"if\s*\([^)]+\)\s*\{\s*return\s+(-?\d+|NULL|0x[0-9a-fA-F]+)\s*;"
        ),
        "comment_fn": lambda m, ctx: _logic_early_return(m, ctx),
        "category": "early_return",
    },
    # ---- Cleanup-goto pattern ----
    {
        "pattern": re.compile(
            r"goto\s+(err|error|fail|cleanup|done|out|bail)\w*\s*;"
        ),
        "comment_fn": lambda m, ctx: (
            "jump to cleanup" if m.group(1) == "cleanup"
            else f"jump to {m.group(1)} cleanup"
        ),
        "category": "error_cleanup",
    },
    # ---- Cleanup label ----
    {
        "pattern": re.compile(
            r"^(err|error|fail|cleanup|done|out|bail)\w*\s*:"
        ),
        "comment": "error/cleanup path",
        "category": "error_cleanup",
    },
    # ---- open() file ----
    {
        "pattern": re.compile(
            r"open\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)"
        ),
        "comment_fn": lambda m, ctx: _logic_open(m, ctx),
        "category": "file_io",
    },
    # ---- socket() create ----
    {
        "pattern": re.compile(
            r"socket\s*\(\s*(AF_\w+|PF_\w+|\d+)\s*,"
        ),
        "comment_fn": lambda m, ctx: _logic_socket(m, ctx),
        "category": "network",
    },
    # ---- pthread_mutex_lock ----
    {
        "pattern": re.compile(
            r"pthread_mutex_lock\s*\(\s*&?\s*(\w+)\s*\)"
        ),
        "comment_fn": lambda m, ctx: f"acquire lock {m.group(1)}",
        "category": "sync",
    },
    # ---- pthread_mutex_unlock ----
    {
        "pattern": re.compile(
            r"pthread_mutex_unlock\s*\(\s*&?\s*(\w+)\s*\)"
        ),
        "comment_fn": lambda m, ctx: f"release lock {m.group(1)}",
        "category": "sync",
    },
    # ---- Bit manipulation ----
    {
        "pattern": re.compile(
            r"(\w+)\s*(?:&=|&)\s*(?:~\s*)?(?:0x[0-9a-fA-F]+|\d+)"
        ),
        "comment_fn": lambda m, ctx: _logic_bitmask(m, ctx),
        "category": "bitwise",
    },
    # ---- sizeof usage (struct/buffer size) ----
    {
        "pattern": re.compile(
            r"sizeof\s*\(\s*(\w+)\s*\)"
        ),
        # sizeof is often part of malloc/memcpy; no standalone comment needed
        # This is intentionally left without comment to avoid over-commenting
        "comment": "",
        "category": "skip",
    },
]

# Compile logic patterns
_LOGIC_COMPILED: list[tuple[re.Pattern, Any, str]] = []
for _lp in LOGIC_COMMENT_PATTERNS:
    if _lp.get("category") == "skip":
        continue
    _LOGIC_COMPILED.append(
        (_lp["pattern"], _lp.get("comment_fn") or _lp.get("comment", ""), _lp["category"])
    )


def _format_iter_bound(bound: str) -> str:
    """Loop sinir degerini okunabilir formata donustur."""
    # Hex literal
    hex_match = re.match(r"^0x([0-9a-fA-F]+)$", bound)
    if hex_match:
        try:
            decimal = int(hex_match.group(1), 16)
            return f"{decimal} ({bound})"
        except ValueError:
            pass
    return bound


def _logic_error_return(m: re.Match, ctx: str) -> str:
    """if (x < 0) pattern'inin return icerip icermedigine bak."""
    # Satirdan sonraki birkaç satira bak
    rest = ctx[m.end():][:200]
    if re.search(r"return\s+(-1|0|NULL|false)", rest[:150]):
        return f"error check: return on {m.group(1)} failure"
    return f"check {m.group(1)} for negative value"


def _logic_nonzero_check(m: re.Match, ctx: str) -> str:
    """if (x != 0) pattern'i -- errno style error check."""
    rest = ctx[m.end():][:200]
    if re.search(r"return\s+(-1|0|NULL|false)|goto\s+\w+", rest[:150]):
        return f"error check: handle {m.group(1)} != 0"
    return ""


def _logic_null_check(m: re.Match, ctx: str) -> str:
    """if (ptr == NULL) pattern'inin hangi path'e gittigine bak."""
    var = m.group(1)
    rest = ctx[m.end():][:200]
    if re.search(r"return\s+(-1|0|NULL|false)", rest[:150]):
        return f"null check: return on {var} == NULL"
    if re.search(r"goto\s+\w+", rest[:150]):
        return f"null check: {var} -- jump to cleanup"
    if re.search(r"free\s*\(|exit\s*\(|abort\s*\(", rest[:150]):
        return f"null check: {var} -- abort/cleanup"
    return f"null check on {var}"


def _logic_while_break(m: re.Match, ctx: str) -> str:
    """while(1) icerisinde break kosulunu bul."""
    rest = ctx[m.end():][:500]
    break_match = re.search(r"if\s*\(\s*([^)]{1,40})\s*\)\s*(?:\{?\s*break|break)", rest)
    if break_match:
        cond = break_match.group(1).strip()
        if len(cond) <= 30:
            return f"loop until {cond}"
    return "event/main loop"


def _logic_alloc_pattern(m: re.Match, ctx: str) -> str:
    """malloc/calloc sonrasi null check varsa 'allocate + check' yaz."""
    var = m.group(1)
    rest = ctx[m.end():][:200]
    if re.search(rf"if\s*\(\s*{re.escape(var)}\s*==\s*(?:NULL|0)", rest):
        return f"allocate memory for {var} (checked)"
    return f"allocate memory for {var}"


def _logic_strcmp(m: re.Match, ctx: str) -> str:
    """strcmp sonucuna gore karsilastirilan degeri yaz."""
    arg2 = m.group(2).strip().strip('"')
    if len(arg2) <= 25:
        return f'compare {m.group(1)} with "{arg2}"'
    return f"compare strings"


def _logic_early_return(m: re.Match, ctx: str) -> str:
    """Early return degerine gore anlam cikar."""
    retval = m.group(1)
    if retval in ("-1", "NULL", "0x0"):
        return "early return on failure"
    if retval == "0":
        return "early return on success"
    return f"early return ({retval})"


def _logic_open(m: re.Match, ctx: str) -> str:
    """open() cagrisinin flag'lerine bak."""
    flags = m.group(2).strip()
    if "O_RDONLY" in flags or "0" == flags.strip():
        return "open file for reading"
    if "O_WRONLY" in flags:
        return "open file for writing"
    if "O_RDWR" in flags:
        return "open file for read/write"
    if "O_CREAT" in flags:
        return "open/create file"
    return "open file"


def _logic_socket(m: re.Match, ctx: str) -> str:
    """socket() domain'ine gore aciklama uret."""
    domain = m.group(1)
    if "INET6" in domain:
        return "create IPv6 network socket"
    if "INET" in domain:
        return "create network socket"
    if "UNIX" in domain or "LOCAL" in domain:
        return "create unix domain socket"
    return "create socket"


def _logic_bitmask(m: re.Match, ctx: str) -> str:
    """Bit maskeleme islemlerini tani.

    Sadece &= veya & ~ gibi flag islemleri icin yorum uret.
    Normal aritmetik islemleri (a + b, x * y) filtrelenir.
    """
    line = ctx[m.start():m.end()]
    if "&=" in line:
        if "~" in line:
            return "clear bit flag"
        return "mask bits"
    # Standalone & (non-assignment) -- genellikle karsilastirma icinde
    return ""


def _logic_bounds_check(m: re.Match, ctx: str) -> str:
    """Bounds check: if (x >= limit) veya if (x > limit)."""
    var = m.group(1)
    bound = m.group(2)
    rest = ctx[m.end():][:150]
    if re.search(r"return|goto|break", rest[:100]):
        return f"bounds check: {var} against {bound}"
    return ""


# ---------------------------------------------------------------------------
# Fonksiyon regex'i (Ghidra decompile ciktisi)
# ---------------------------------------------------------------------------

# Ghidra formati: "{" genellikle AYRI satirda olur:
#   void FUN_100001e40(void)
#
#   {
# Bu yuzden regex'te "{" zorunlu degil. Fonksiyon imzasini yakalar,
# ardindan _is_function_def() ile sonraki satirlarda "{" kontrol edilir.
_FUNC_SIG_RE = re.compile(
    r"^(?:(?:void|int|uint|long|ulong|char|uchar|short|ushort|byte|bool|float|double|"
    r"size_t|ssize_t|undefined\d?|code\s*\*|undefined\s*\*|"
    r"\w+\s*\*+)\s+)"
    r"(\w+)\s*\(([^)]*)\)\s*\{?",
    re.MULTILINE,
)

# Eski alias -- eskiden { ayni satirda zorunluydu, artik opsiyonel.
_FUNC_RE = _FUNC_SIG_RE


# ---------------------------------------------------------------------------
# ProcessPoolExecutor worker'lari -- top-level (pickle edilebilir)
# ---------------------------------------------------------------------------

_worker_generator: "CCommentGenerator | None" = None
_worker_shared: dict[str, Any] = {}


def _init_comment_worker(
    generator: "CCommentGenerator",
    func_meta: dict[str, Any],
    string_refs: dict[str, Any],
    call_graph: dict[str, Any],
    algo_index: dict[str, Any],
    cfg_index: dict[str, Any] | None,
    formula_index: dict[str, Any] | None,
    output_dir_str: str,
) -> None:
    """ProcessPoolExecutor initializer -- her worker process'te bir kez calisir.

    Buyuk read-only dict'ler burada global'e atanir, boylece her dosya
    icin ayri pickle/unpickle yapilmaz (fork COW'dan faydalanir).
    """
    global _worker_generator, _worker_shared
    _worker_generator = generator
    _worker_shared = {
        "func_meta": func_meta,
        "string_refs": string_refs,
        "call_graph": call_graph,
        "algo_index": algo_index,
        "cfg_index": cfg_index,
        "formula_index": formula_index,
        "output_dir": output_dir_str,
    }


def _annotate_file_worker(c_file_path: str) -> tuple[str | None, dict[str, int] | None, str | None]:
    """Tek bir C dosyasini annotate et (process-safe).

    ProcessPoolExecutor icin top-level fonksiyon.  Shared state initializer
    ile _worker_generator ve _worker_shared'e atanmistir.

    Returns:
        (output_path_str | None, counters | None, error_msg | None)
    """
    gen = _worker_generator
    shared = _worker_shared
    c_file = Path(c_file_path)

    try:
        content = c_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, None, f"Cannot read {c_file.name}: {exc}"

    annotated, file_counters = gen._annotate_file(  # type: ignore[union-attr]
        content=content,
        func_meta=shared["func_meta"],
        string_refs=shared["string_refs"],
        call_graph=shared["call_graph"],
        algo_index=shared["algo_index"],
        filename=c_file.name,
        cfg_index=shared["cfg_index"],
        formula_index=shared["formula_index"],
    )

    output_path = Path(shared["output_dir"]) / c_file.name
    try:
        output_path.write_text(annotated, encoding="utf-8")
    except OSError as exc:
        return None, None, f"Cannot write {output_path.name}: {exc}"

    return str(output_path), file_counters, None


# ---------------------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------------------

class CCommentGenerator:
    """Ghidra decompile ciktisina akilli yorumlar ekler.

    Yorum tipleri:
    1. Function header block (doxygen-benzeri)
    2. System call annotations (malloc, open, socket vb.)
    3. Vulnerability warnings (strcpy, gets, sprintf vb.)
    4. Control flow annotations (state machine, infinite loop vb.)
    5. Algorithm labels (c_algorithm_id sonuclarindan)
    6. Logic comments -- blok seviyesi mantik yorumlari (error check,
       loop purpose, memory alloc, string compare, branch summary vb.)

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()

    def generate(
        self,
        decompiled_dir: Path,
        output_dir: Path,
        functions_json: Path | None = None,
        strings_json: Path | None = None,
        call_graph_json: Path | None = None,
        algorithm_results: list[AlgorithmMatch] | None = None,
        cfg_matches: list[dict] | None = None,
        formulas_extracted: list[dict] | None = None,
    ) -> CCommentResult:
        """Ana yorum uretme fonksiyonu.

        Args:
            decompiled_dir: Decompile edilmis C dosyalarinin bulundugu dizin.
            output_dir: Yorumlu dosyalarin yazilacagi dizin.
            functions_json: Fonksiyon metadata (Ghidra ciktisi). Opsiyonel.
            strings_json: String referanslari. Opsiyonel.
            call_graph_json: Cagri grafigi. Opsiyonel.
            algorithm_results: c_algorithm_id'den tespit edilen algoritmalar. Opsiyonel.
            cfg_matches: Computation Recovery CFG fingerprint eslestirmeleri. Opsiyonel.
                Her eleman {"function_name", "matched_algorithm", "confidence", ...} dict.
            formulas_extracted: Computation Recovery formula extraction sonuclari. Opsiyonel.
                Her eleman {"function_name", "ascii", "formula_type", "confidence", ...} dict.

        Returns:
            CCommentResult: Yorum ekleme sonuclari.
        """
        errors: list[str] = []
        output_files: list[Path] = []
        counters = {
            "headers": 0,
            "syscalls": 0,
            "vulns": 0,
            "algos": 0,
            "control": 0,
            "logic": 0,
            "computation": 0,
        }

        # Cikti dizinini olustur
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return CCommentResult(
                success=False,
                errors=[f"Cannot create output directory: {exc}"],
            )

        # Metadata yukle ve Ghidra JSON formatindan indexle
        raw_func_meta = self._load_json(functions_json, errors)
        raw_string_refs = self._load_json(strings_json, errors)
        raw_call_graph = self._load_json(call_graph_json, errors)

        # Ghidra JSON'lari {total, program, functions/strings/edges} formatinda.
        # Bunlari fonksiyon ismine gore indexle.
        func_meta = self._index_functions(raw_func_meta)
        string_refs = self._index_strings(raw_string_refs)
        call_graph = self._index_call_graph(raw_call_graph)

        # Algoritma sonuclarini fonksiyon bazli indexle
        algo_index = self._index_algorithms(algorithm_results or [])

        # Computation Recovery verilerini fonksiyon bazli indexle
        cfg_index = self._index_cfg_matches(cfg_matches or [])
        formula_index = self._index_formulas(formulas_extracted or [])

        # C dosyalarini topla
        c_files = self._collect_c_files(decompiled_dir, errors)
        if not c_files:
            return CCommentResult(
                success=False,
                errors=errors or ["No C files found in decompiled directory"],
            )

        from concurrent.futures import (
            BrokenExecutor,
            ProcessPoolExecutor,
            as_completed,
        )

        num_workers = CPU_PERF_CORES
        file_paths = [str(f) for f in c_files]
        logger.info(
            "C comment generation: %d files (%d processes)",
            len(file_paths), num_workers,
        )

        results: list[tuple[str | None, dict[str, int] | None, str | None]] = []
        with ProcessPoolExecutor(
            max_workers=num_workers,
            initializer=_init_comment_worker,
            initargs=(
                self,
                func_meta,
                string_refs,
                call_graph,
                algo_index,
                cfg_index,
                formula_index,
                str(output_dir),
            ),
        ) as pool:
            futs = {
                pool.submit(_annotate_file_worker, fp): fp
                for fp in file_paths
            }
            try:
                for fut in as_completed(futs, timeout=1200):
                    try:
                        result = fut.result(timeout=300)
                    except TimeoutError:
                        errors.append(f"Comment worker timeout: {futs[fut]}")
                        continue
                    except Exception as exc:
                        errors.append(f"Comment worker error ({futs[fut]}): {exc}")
                        continue
                    results.append(result)
            except TimeoutError:
                errors.append(
                    "Comment generation total timeout (1200s) exceeded, "
                    "some files may not have been processed"
                )
            except BrokenExecutor as exc:
                errors.append(f"ProcessPool crash: {exc}")

        for out_path, file_counters, err in results:
            if err:
                errors.append(err)
                continue
            if out_path:
                output_files.append(Path(out_path))
            if file_counters:
                for key in counters:
                    counters[key] += file_counters.get(key, 0)

        total = sum(counters.values())
        logger.info(
            "C comment generation: %d comments added (%d headers, %d syscalls, "
            "%d vulns, %d algos, %d control, %d logic, %d computation)",
            total,
            counters["headers"],
            counters["syscalls"],
            counters["vulns"],
            counters["algos"],
            counters["control"],
            counters.get("logic", 0),
            counters.get("computation", 0),
        )

        return CCommentResult(
            success=True,
            output_files=output_files,
            total_comments_added=total,
            function_headers=counters["headers"],
            syscall_annotations=counters["syscalls"],
            vulnerability_warnings=counters["vulns"],
            algorithm_labels=counters["algos"],
            control_flow_annotations=counters["control"],
            logic_comments=counters.get("logic", 0),
            computation_annotations=counters.get("computation", 0),
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Dosya isleme
    # ------------------------------------------------------------------

    def _annotate_file(
        self,
        content: str,
        func_meta: dict[str, Any],
        string_refs: dict[str, Any],
        call_graph: dict[str, Any],
        algo_index: dict[str, list[AlgorithmMatch]],
        filename: str,
        cfg_index: dict[str, list[dict]] | None = None,
        formula_index: dict[str, list[dict]] | None = None,
    ) -> tuple[str, dict[str, int]]:
        """Tek bir C dosyasini isle ve yorumlar ekle.

        Returns:
            (yorumlanmis_icerik, sayac_dict)
        """
        lines = content.split("\n")
        insertions: list[tuple[int, str]] = []
        counters = {"headers": 0, "syscalls": 0, "vulns": 0, "algos": 0, "control": 0,
                     "logic": 0, "computation": 0}

        # Fonksiyon baslangiclari bul
        # Ghidra formati: "{" genellikle AYRI satirda olur (bos satirdan sonra bile).
        # Ornekler:
        #   void FUN_100001e40(void)     <- imza satiri
        #                                <- bos satir
        #   {                            <- acilis braces
        # veya:
        #   void func(int x) {           <- tek satirda (nadiren)
        func_starts: list[tuple[int, str, str]] = []  # (line_no, name, params)
        for i, line in enumerate(lines):
            match = _FUNC_SIG_RE.match(line)
            if match:
                # Regex "{" opsiyonel yakaliyor. Ayni satirda varsa kesin fonksiyon.
                # Yoksa sonraki 3 satirda "{" var mi kontrol et (Ghidra formati).
                has_brace = "{" in line[match.end() - 1:] if match.end() > 0 else False
                if not has_brace:
                    # Sonraki 3 satira bak -- bos satirlardan sonra "{" gelebilir
                    found_brace = False
                    for j in range(i + 1, min(i + 4, len(lines))):
                        stripped_next = lines[j].strip()
                        if stripped_next == "{":
                            found_brace = True
                            break
                        elif stripped_next == "":
                            continue  # Bos satirlari atla
                        else:
                            break  # Bos olmayan, "{" olmayan satirda dur
                    if not found_brace:
                        continue  # Bu bir fonksiyon tanimi degil
                func_starts.append((i, match.group(1), match.group(2)))

        # Her fonksiyon icin header block ekle
        for line_no, func_name, params in func_starts:
            # Onceki satir zaten yorum mu?
            if line_no > 0 and lines[line_no - 1].strip().endswith("*/"):
                continue

            header = self._build_function_header(
                func_name=func_name,
                params=params,
                func_meta=func_meta,
                string_refs=string_refs,
                call_graph=call_graph,
                algo_index=algo_index,
                filename=filename,
            )
            if header:
                insertions.append((line_no, header))
                counters["headers"] += 1

        # Satirlik yorumlar: syscall, vuln, logic, control flow
        # Her satirda en fazla BIR yorum eklenir (oncelik: vuln > syscall > logic > control)
        for i, line in enumerate(lines):
            stripped = line.strip()

            # Zaten yorumlu satiri atla
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            indent = line[:len(line) - len(line.lstrip())]

            # Vulnerability check (oncelikli)
            vuln_comment = self._check_vulnerability(stripped)
            if vuln_comment:
                insertions.append((i, f"{indent}/* {vuln_comment} */"))
                counters["vulns"] += 1
                continue  # Bir satirda bir yorum yeter

            # Syscall annotation
            syscall_comment = self._check_syscall(stripped)
            if syscall_comment:
                insertions.append((i, f"{indent}/* {syscall_comment} */"))
                counters["syscalls"] += 1
                continue

            # Logic comment -- blok seviyesi mantik yorumu
            # Surrounding context: satirdan sonraki 300 karakteri ver
            line_offset = sum(len(lines[j]) + 1 for j in range(i))
            ctx_after = content[line_offset:line_offset + 500]
            logic_comment = self._check_logic_pattern(stripped, ctx_after)
            if logic_comment:
                insertions.append((i, f"{indent}/* {logic_comment} */"))
                counters["logic"] += 1
                continue

            # Control flow annotation
            cf_comment = self._check_control_flow(stripped, content)
            if cf_comment:
                insertions.append((i, f"{indent}/* {cf_comment} */"))
                counters["control"] += 1

        # Algoritma label'lari: fonksiyon body basindaki ilk satira
        for line_no, func_name, _ in func_starts:
            if func_name in algo_index:
                algos = algo_index[func_name]
                for algo in algos:
                    label = f"/* ALGORITHM: {algo.name} (confidence: {algo.confidence:.0%}, via {algo.detection_method}) */"
                    # Fonksiyon acilis { 'den sonraki satira ekle
                    insert_at = line_no + 1
                    if insert_at < len(lines):
                        indent = "    "
                        insertions.append((insert_at, f"{indent}{label}"))
                        counters["algos"] += 1

        # Computation Recovery yorumlari: CFG fingerprint + formula
        # Fonksiyon header blogundan hemen sonra (imza satirinin ustune) eklenir.
        for line_no, func_name, _ in func_starts:
            comp_comments: list[str] = []

            # CFG fingerprint eslesmesi: DEVRE DISI (v1.5.3)
            # 138 template arasi discriminability yetersiz (margin < 0.05).
            # Yanlis spesifik isim, dogru genel profilden daha zararli.
            # Pcode classify (6 profil) primary source olarak kullaniliyor.
            # CFG matching sadece WL hash exact match icin aktif (nadir).
            if cfg_index and func_name in cfg_index:
                func_cfg = cfg_index[func_name]
                best = max(func_cfg, key=lambda m: m.get("confidence", 0))
                # Sadece WL structure hash exact match (hash_matched flag)
                if best.get("hash_matched", False) and best.get("confidence", 0) > 0.97:
                    comp_comments.append(
                        "// [Computation] CFG exact match: %s (hash verified)"
                        % best.get("matched_algorithm", "unknown")
                    )

            # Formula extraction sonuclari (max 3 per function)
            if formula_index and func_name in formula_index:
                func_formulas = formula_index[func_name]
                for formula in func_formulas[:3]:
                    expr = formula.get("ascii", "")
                    if expr:
                        ftype = formula.get("formula_type", "")
                        suffix = f" [{ftype}]" if ftype else ""
                        comp_comments.append(
                            "// [Computation] Formula: %s%s" % (expr, suffix)
                        )

            # Yorum satirlarini fonksiyon imzasinin hemen ustune ekle
            for comment in comp_comments:
                insertions.append((line_no, comment))
                counters["computation"] += 1

        # Sirayla ekle (sondan basa)
        insertions.sort(key=lambda x: x[0], reverse=True)
        for line_no, comment_text in insertions:
            lines.insert(line_no, comment_text)

        return "\n".join(lines), counters

    # ------------------------------------------------------------------
    # Fonksiyon header block olusturma
    # ------------------------------------------------------------------

    def _build_function_header(
        self,
        func_name: str,
        params: str,
        func_meta: dict[str, Any],
        string_refs: dict[str, Any],
        call_graph: dict[str, Any],
        algo_index: dict[str, list[AlgorithmMatch]],
        filename: str = "",
    ) -> str:
        """Doxygen-benzeri fonksiyon baslik yorumu olustur.

        Ornek cikti:
        /**
         * @brief Validates SSL certificate chain
         * @address 0x00143a90
         * @size 256 bytes
         * @called_by handle_tls_handshake (3 sites)
         * @calls X509_verify_cert, SSL_get_peer_certificate
         * @strings "certificate validation failed", "expired cert"
         * @algorithm RSA signature verification (detected)
         * @security Handles sensitive crypto material
         */
        """
        parts: list[str] = ["/**"]

        # Metadata lookup: fonksiyon adi ile dene, bulamazsa dosya adindan
        # orijinal Ghidra ismini cikar (dosya: FUN_1000019c0.c -> FUN_1000019c0)
        meta = func_meta.get(func_name, {})
        if not meta and filename:
            ghidra_name = filename.rsplit(".", 1)[0]  # .c uzantisini kaldir
            meta = func_meta.get(ghidra_name, {})

        # Orijinal Ghidra ismini de hesapla (call graph ve string lookup icin)
        ghidra_name = ""
        if filename:
            ghidra_name = filename.rsplit(".", 1)[0]

        # Call graph ve string bilgilerini brief'ten once hazirla
        cg_entry = call_graph.get(func_name) or (call_graph.get(ghidra_name) if ghidra_name else None) or {}
        callees = cg_entry.get("callees", [])
        func_strings = string_refs.get(func_name) or (string_refs.get(ghidra_name, []) if ghidra_name else [])

        # String referanslarini duzlestir (list[dict] -> list[str] olabilir)
        flat_strings: list[str] = []
        if func_strings:
            for s in func_strings:
                if isinstance(s, dict):
                    flat_strings.append(s.get("value", s.get("string", "")))
                else:
                    flat_strings.append(str(s))

        # @brief -- API profil + string domain ile akilli aciklama
        brief = self._build_smart_brief(func_name, callees, flat_strings or None)
        parts.append(f" * @brief {brief}")

        # @address -- metadata'dan
        address = meta.get("address") or meta.get("entry_point")
        if address:
            parts.append(f" * @address {address}")
        elif func_name.startswith("FUN_"):
            parts.append(f" * @address 0x{func_name[4:]}")

        # @size
        size = meta.get("size") or meta.get("length")
        if size:
            parts.append(f" * @size {size} bytes")

        # @params
        if params.strip() and params.strip() != "void":
            param_list = [p.strip() for p in params.split(",") if p.strip()]
            for p in param_list:
                parts.append(f" * @param {p}")

        # @called_by -- cagri grafiginden
        callers = cg_entry.get("callers", [])
        if callers:
            caller_str = ", ".join(callers[:5])
            site_count = len(callers)
            parts.append(f" * @called_by {caller_str} ({site_count} site{'s' if site_count > 1 else ''})")

        # @calls -- cagri grafiginden
        if callees:
            callee_str = ", ".join(callees[:8])
            parts.append(f" * @calls {callee_str}")

        # @strings -- ilgili string referanslari (flat_strings yukarda hazirlandı)
        if flat_strings:
            str_list = [f'"{s}"' for s in flat_strings[:5]]
            parts.append(f" * @strings {', '.join(str_list)}")

        # @algorithm -- tespit edilen algoritmalar
        if func_name in algo_index:
            for algo in algo_index[func_name]:
                parts.append(
                    f" * @algorithm {algo.name} ({algo.category}, "
                    f"confidence: {algo.confidence:.0%})"
                )

        # @security -- hassas islev tespiti
        security_note = self._detect_security_relevance(func_name, params)
        if security_note:
            parts.append(f" * @security {security_note}")

        parts.append(" */")

        # Cok kisa header'lari atla (sadece brief varsa ve generic ise)
        if len(parts) <= 4 and "FUN_" in func_name:
            return ""

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Satirlik yorum kontrolleri
    # ------------------------------------------------------------------

    # Modul seviyesinde onceden compile — tek combined regex
    _SYSCALL_COMBINED = re.compile(
        r"\b(" + "|".join(
            re.escape(n) for n in sorted(SYSCALL_DOCS.keys(), key=len, reverse=True)
        ) + r")\s*\(([^)]*)\)"
    ) if SYSCALL_DOCS else None

    @staticmethod
    def _check_syscall(line: str) -> str:
        """Satirda bilinen bir sistem cagrisi varsa aciklama dondur."""
        if not CCommentGenerator._SYSCALL_COMBINED:
            return ""
        match = CCommentGenerator._SYSCALL_COMBINED.search(line)
        if not match:
            return ""
        func_name = match.group(1)
        args = match.group(2).strip()
        doc_template = SYSCALL_DOCS.get(func_name, "")
        if not doc_template:
            return ""

        arg_list = [a.strip() for a in args.split(",") if a.strip()]
        doc = doc_template
        for i, arg in enumerate(arg_list):
            placeholder = f"{{arg{i}}}"
            if placeholder in doc:
                doc = doc.replace(placeholder, _format_arg(arg))
        doc = re.sub(r"\{arg\d+\}", "?", doc)
        return f"{func_name}: {doc}"

    @staticmethod
    def _check_vulnerability(line: str) -> str:
        """Satirda bilinen bir guvenlik acigi pattern'i varsa uyari dondur."""
        for pattern, warning, severity in _VULN_COMPILED:
            if pattern.search(line):
                return f"[{severity}] {warning}"
        return ""

    @staticmethod
    def _check_control_flow(line: str, full_content: str) -> str:
        """Satirda kontrol akisi pattern'i varsa aciklama dondur."""
        for cf in CONTROL_FLOW_PATTERNS:
            match = cf["pattern"].search(line)
            if match:
                if "comment_fn" in cf:
                    return cf["comment_fn"](match, full_content)
                return cf["comment"]
        return ""

    @staticmethod
    def _check_logic_pattern(line: str, context_after: str) -> str:
        """Satirda mantiksal blok pattern'i varsa aciklama dondur.

        Mevcut syscall/vuln/control flow annotation'lardan farkli olarak,
        bu metod KOD BLOGUNU (if/for/while/return) anlar ve ne yaptigini
        aciklar: error check, loop purpose, memory alloc, string compare vb.

        Args:
            line: Kontrol edilecek satir (stripped).
            context_after: Satirdan sonraki ~500 karakter (break/return aramasi icin).

        Returns:
            Bos string (eslesmez) veya kisa (<60 char) yorum metni.
        """
        for pattern, comment_or_fn, category in _LOGIC_COMPILED:
            match = pattern.search(line)
            if not match:
                continue
            # comment_fn veya sabit comment
            if callable(comment_or_fn):
                result = comment_or_fn(match, context_after)
            else:
                result = comment_or_fn
            # Bos sonuc: bu pattern eslesti ama yorum uretmedi (filtrelendi)
            if not result:
                continue
            # Uzunluk siniri: max 60 karakter
            if len(result) > 60:
                result = result[:57] + "..."
            return result
        return ""

    # ------------------------------------------------------------------
    # Yardimci fonksiyonlar
    # ------------------------------------------------------------------

    def _build_smart_brief(
        self, func_name: str, callees: list[str],
        string_refs: list[str] | None = None,
    ) -> str:
        """API profil + string domain ile akilli @brief olustur.

        Callee listesi function_summary_patterns'teki 50+ API combo
        pattern'iyle karsilastirilir. Eslesen varsa o ozet kullanilir,
        yoksa fallback olarak _name_to_description cagirilir.
        """
        from karadul.reconstruction.function_summary_patterns import match_function_summary

        callee_set = set(callees) if callees else set()
        result = match_function_summary(callee_set, string_refs)

        if result:
            summary, conf = result
            return summary

        # Fallback: mevcut isim-tabanli aciklama
        return self._name_to_description(func_name)

    @staticmethod
    def _name_to_description(func_name: str) -> str:
        """Fonksiyon adindan kisa aciklama olustur.

        Ghidra isimlendirme konvansiyonlarini anlar:
        - FUN_XXXXXXXX -> "Function at address 0xXXXXXXXX"
        - _symbol_name -> "Internal: symbol_name"
        - camelCase/snake_case parcalama
        """
        if not func_name:
            return "Unknown function"

        # Ghidra generated
        if func_name.startswith("FUN_"):
            return f"Function at address 0x{func_name[4:]}"

        # Ghidra thunk/entry
        if func_name.startswith("entry"):
            return "Program entry point"
        if func_name == "main":
            return "Program main entry point"

        # Internal symbol
        if func_name.startswith("_"):
            clean = func_name.lstrip("_")
            return f"Internal: {_split_name(clean)}"

        return _split_name(func_name).capitalize()

    @staticmethod
    def _detect_security_relevance(func_name: str, params: str) -> str:
        """Fonksiyonun guvenlikle ilgili olup olmadigini kontrol et."""
        name_lower = func_name.lower()

        if any(kw in name_lower for kw in ("crypt", "cipher", "aes", "rsa", "sha", "hash")):
            return "Handles cryptographic operations"
        if any(kw in name_lower for kw in ("auth", "login", "password", "credential", "token")):
            return "Handles authentication/credentials"
        if any(kw in name_lower for kw in ("key", "secret", "private")):
            return "Handles sensitive key material"
        if any(kw in name_lower for kw in ("cert", "x509", "ssl", "tls")):
            return "Handles certificates/TLS"
        if any(kw in name_lower for kw in ("sandbox", "entitle", "privilege", "root")):
            return "Handles privilege/sandbox operations"
        if any(kw in name_lower for kw in ("inject", "hook", "patch", "detour")):
            return "Code injection/hooking mechanism"

        # Parametre bazli tespit
        param_lower = params.lower()
        if any(kw in param_lower for kw in ("password", "key", "secret", "token")):
            return "Receives sensitive parameters"

        return ""

    @staticmethod
    def _index_algorithms(
        algorithms: list[AlgorithmMatch],
    ) -> dict[str, list[AlgorithmMatch]]:
        """Algoritma sonuclarini fonksiyon adi bazli indexle."""
        index: dict[str, list[AlgorithmMatch]] = {}
        for algo in algorithms:
            if algo.function_name not in index:
                index[algo.function_name] = []
            index[algo.function_name].append(algo)
        return index

    @staticmethod
    def _index_cfg_matches(
        matches: list[dict],
    ) -> dict[str, list[dict]]:
        """CFG fingerprint eslesmelerini fonksiyon adi bazli indexle.

        Her dict: {"function_name": "...", "matched_algorithm": "...", "confidence": 0.9, ...}
        """
        index: dict[str, list[dict]] = {}
        for m in matches:
            fname = m.get("function_name", "")
            if fname:
                if fname not in index:
                    index[fname] = []
                index[fname].append(m)
        return index

    @staticmethod
    def _index_formulas(
        formulas: list[dict],
    ) -> dict[str, list[dict]]:
        """Cikarilan formulleri fonksiyon adi bazli indexle.

        Her dict: {"function_name": "...", "ascii": "...", "formula_type": "...", ...}
        """
        index: dict[str, list[dict]] = {}
        for f in formulas:
            fname = f.get("function_name", "")
            if fname:
                if fname not in index:
                    index[fname] = []
                index[fname].append(f)
        return index

    @staticmethod
    def _index_functions(raw: dict[str, Any]) -> dict[str, Any]:
        """Ghidra functions JSON'unu fonksiyon ismine gore indexle.

        Ghidra formati: {"total": N, "program": "...", "functions": [{"name": "FUN_xxx", "address": "...", ...}]}
        Cikti: {"FUN_xxx": {"address": "...", "size": N, ...}, ...}

        Eger raw zaten fonksiyon ismine gore indexlenmisse (eski format), aynen dondur.
        """
        if not raw:
            return {}
        # Ghidra formati: functions listesi var
        functions = raw.get("functions")
        if isinstance(functions, list):
            result: dict[str, Any] = {}
            for func in functions:
                if isinstance(func, dict) and "name" in func:
                    result[func["name"]] = func
            return result
        # Eger "functions" yoksa, zaten fonksiyon ismine gore indexli olabilir
        # veya tanimlanamiyor -- raw'i dondur
        return raw

    @staticmethod
    def _index_strings(raw: dict[str, Any]) -> dict[str, Any]:
        """Ghidra strings JSON'unu fonksiyon referansina gore indexle.

        Ghidra formati iki cesit olabilir:
        1. {"strings": [{"value": "...", "function": "FUN_xxx", ...}]}
        2. {"strings": [{"value": "...", "xrefs": [{"function": "..."}]}]}

        Cikti: {"func_name": ["string1", "string2"], ...}
        """
        if not raw:
            return {}
        strings = raw.get("strings")
        if not isinstance(strings, list):
            return raw
        result: dict[str, list[str]] = {}
        for entry in strings:
            if not isinstance(entry, dict):
                continue
            value = entry.get("value", "")
            if not value:
                continue

            # Format 1: dogrudan "function" field'i
            func_name = entry.get("function")
            if func_name:
                if func_name not in result:
                    result[func_name] = []
                if value not in result[func_name]:
                    result[func_name].append(value)
                continue

            # Format 2: xrefs listesi
            xrefs = entry.get("xrefs", [])
            if not xrefs:
                continue
            for xref in xrefs:
                fn = None
                if isinstance(xref, dict):
                    fn = xref.get("function") or xref.get("func_name")
                elif isinstance(xref, str):
                    fn = xref
                if fn:
                    if fn not in result:
                        result[fn] = []
                    if value not in result[fn]:
                        result[fn].append(value)
        return result

    @staticmethod
    def _index_call_graph(raw: dict[str, Any]) -> dict[str, Any]:
        """Ghidra call_graph JSON'unu fonksiyon ismine gore indexle.

        Ghidra formati: {"nodes": [...], "edges": [{"from_name": "A", "to_name": "B"}]}
        Cikti: {"func_name": {"callers": [...], "callees": [...]}, ...}
        """
        if not raw:
            return {}
        edges = raw.get("edges")
        if not isinstance(edges, list):
            return raw
        result: dict[str, dict[str, list[str]]] = {}
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            caller = edge.get("from_name", "")
            callee = edge.get("to_name", "")
            if caller:
                if caller not in result:
                    result[caller] = {"callers": [], "callees": []}
                if callee and callee not in result[caller]["callees"]:
                    result[caller]["callees"].append(callee)
            if callee:
                if callee not in result:
                    result[callee] = {"callers": [], "callees": []}
                if caller and caller not in result[callee]["callers"]:
                    result[callee]["callers"].append(caller)
        return result

    @staticmethod
    def _collect_c_files(directory: Path, errors: list[str]) -> list[Path]:
        """Dizindeki C/H dosyalarini topla."""
        if not directory.exists():
            errors.append(f"Directory does not exist: {directory}")
            return []
        files: list[Path] = []
        for ext in ("*.c", "*.h", "*.cpp", "*.cc"):
            files.extend(directory.glob(ext))
        for ext in ("**/*.c", "**/*.h", "**/*.cpp", "**/*.cc"):
            for f in directory.glob(ext):
                if f not in files:
                    files.append(f)
        return sorted(files)

    @staticmethod
    def _load_json(
        path: Path | None, errors: list[str],
    ) -> dict[str, Any]:
        """JSON dosyasini yukle, hata olursa bos dict dondur."""
        if path is None or not path.exists():
            return {}
        try:
            with open(path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"Cannot load {path.name}: {exc}")
            return {}


# ---------------------------------------------------------------------------
# Modul seviyesi yardimci fonksiyonlar
# ---------------------------------------------------------------------------

def _split_name(name: str) -> str:
    """camelCase veya snake_case ismi bosluklu kelimelere donustur.

    Ornek: "validateSSLCert" -> "validate SSL cert"
            "get_user_data"  -> "get user data"
    """
    # snake_case
    if "_" in name:
        return " ".join(w for w in name.split("_") if w)

    # camelCase / PascalCase
    words = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", name)
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", words)
    return words.lower()


def _format_arg(arg: str) -> str:
    """C arguman degerini okunabilir formata donustur.

    0x100 -> "256 (0x100)"
    sizeof(struct_t) -> aynen birak
    """
    arg = arg.strip()

    # Hex literal
    hex_match = re.match(r"^0x([0-9a-fA-F]+)$", arg)
    if hex_match:
        try:
            decimal = int(hex_match.group(1), 16)
            return f"{decimal} ({arg})"
        except ValueError:
            pass

    return arg
