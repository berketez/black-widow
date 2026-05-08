"""POSIX/system signatures — sig_db v1.13 Dalga 2 migrasyonu (ADR 0007 A1).

Kaynak: karadul/analyzers/signature_db.py
  - _POSIX_FILE_IO_SIGNATURES    -> posix_file_io_signatures
  - _PROCESS_SIGNATURES    -> process_signatures
  - _PTHREAD_SIGNATURES    -> pthread_signatures
  - _MEMORY_SIGNATURES    -> memory_signatures
  - _STRING_STDLIB_SIGNATURES    -> string_stdlib_signatures
  - _TIME_SIGNATURES    -> time_signatures
  - _DYNLOAD_SIGNATURES    -> dynload_signatures
  - _ERROR_LOCALE_MISC_SIGNATURES    -> error_locale_misc_signatures

Toplam: 247 signature (8 dict).

ADR 0007/0008 Tip A yumusak override pattern'i: signature_db.py'de orijinal
dict govdeleri SILINMEDI; runtime'da bu modulden gelen veriyle yeniden
baglanir. Rollback icin override blogu silinince (try/except ImportError)
eski inline veri otomatik geri devreye girer. Birebir parite garanti
(AST literal_eval ile dogrulanir; bkz. tests/test_sigdb_posix_system_migration.py).

Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur:
  ``posix_file_io_signatures``    <-> ``_POSIX_FILE_IO_SIGNATURES``
  ``process_signatures``    <-> ``_PROCESS_SIGNATURES``
  ``pthread_signatures``    <-> ``_PTHREAD_SIGNATURES``
  ``memory_signatures``    <-> ``_MEMORY_SIGNATURES``
  ``string_stdlib_signatures``    <-> ``_STRING_STDLIB_SIGNATURES``
  ``time_signatures``    <-> ``_TIME_SIGNATURES``
  ``dynload_signatures``    <-> ``_DYNLOAD_SIGNATURES``
  ``error_locale_misc_signatures``    <-> ``_ERROR_LOCALE_MISC_SIGNATURES``

NOT: ``_POSIX_NETWORKING_SIGNATURES`` (epoll, kqueue, socket) bu modulde
TASINMADI — zaten ``sigdb_builtin/network.py`` icinde override ediliyor
(signature_db.py satir ~6537). Cifte override cakismasini onlemek icin
network kategorisinde tutuldu.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# posix_file_io_signatures (57 entry) — POSIX low-level + buffered file I/O, dosya sistemi, mmap, pipe.
# Kaynak: signature_db.py _POSIX_FILE_IO_SIGNATURES.
# ---------------------------------------------------------------------------
_POSIX_FILE_IO_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Low-level file descriptors
    "_open": {"lib": "libc", "purpose": "open file descriptor", "category": "file_io"},
    "_close": {"lib": "libc", "purpose": "close file descriptor", "category": "file_io"},
    "_read": {"lib": "libc", "purpose": "read from file descriptor", "category": "file_io"},
    "_write": {"lib": "libc", "purpose": "write to file descriptor", "category": "file_io"},
    "_lseek": {"lib": "libc", "purpose": "seek file descriptor offset", "category": "file_io"},
    "_pread": {"lib": "libc", "purpose": "read at offset (atomic)", "category": "file_io"},
    "_pwrite": {"lib": "libc", "purpose": "write at offset (atomic)", "category": "file_io"},

    # Buffered stdio
    "_fopen": {"lib": "libc", "purpose": "open buffered file stream", "category": "file_io"},
    "_fclose": {"lib": "libc", "purpose": "close buffered file stream", "category": "file_io"},
    "_fread": {"lib": "libc", "purpose": "buffered read from stream", "category": "file_io"},
    "_fwrite": {"lib": "libc", "purpose": "buffered write to stream", "category": "file_io"},
    "_fseek": {"lib": "libc", "purpose": "seek stream position", "category": "file_io"},
    "_ftell": {"lib": "libc", "purpose": "get stream position", "category": "file_io"},
    "_fflush": {"lib": "libc", "purpose": "flush stream buffer", "category": "file_io"},
    "_rewind": {"lib": "libc", "purpose": "rewind stream to beginning", "category": "file_io"},
    "_feof": {"lib": "libc", "purpose": "check end-of-file indicator", "category": "file_io"},
    "_ferror": {"lib": "libc", "purpose": "check stream error indicator", "category": "file_io"},
    "_fgets": {"lib": "libc", "purpose": "read line from stream", "category": "file_io"},
    "_fputs": {"lib": "libc", "purpose": "write string to stream", "category": "file_io"},
    "_fprintf": {"lib": "libc", "purpose": "formatted write to stream", "category": "file_io"},
    "_fscanf": {"lib": "libc", "purpose": "formatted read from stream", "category": "file_io"},
    "_fgetc": {"lib": "libc", "purpose": "read character from stream", "category": "file_io"},
    "_fputc": {"lib": "libc", "purpose": "write character to stream", "category": "file_io"},
    "_ungetc": {"lib": "libc", "purpose": "push character back to stream", "category": "file_io"},

    # File metadata / permissions
    "_stat": {"lib": "libc", "purpose": "get file status by path", "category": "file_io"},
    "_fstat": {"lib": "libc", "purpose": "get file status by fd", "category": "file_io"},
    "_lstat": {"lib": "libc", "purpose": "get symlink status (no follow)", "category": "file_io"},
    "_access": {"lib": "libc", "purpose": "check file accessibility", "category": "file_io"},
    "_chmod": {"lib": "libc", "purpose": "change file permissions", "category": "file_io"},
    "_chown": {"lib": "libc", "purpose": "change file ownership", "category": "file_io"},
    "_chdir": {"lib": "libc", "purpose": "change working directory", "category": "file_io"},
    "_getcwd": {"lib": "libc", "purpose": "get current working directory", "category": "file_io"},

    # Directory operations
    "_mkdir": {"lib": "libc", "purpose": "create directory", "category": "file_io"},
    "_rmdir": {"lib": "libc", "purpose": "remove directory", "category": "file_io"},
    "_opendir": {"lib": "libc", "purpose": "open directory stream", "category": "file_io"},
    "_readdir": {"lib": "libc", "purpose": "read directory entry", "category": "file_io"},
    "_closedir": {"lib": "libc", "purpose": "close directory stream", "category": "file_io"},
    "_scandir": {"lib": "libc", "purpose": "scan directory with filter", "category": "file_io"},

    # File manipulation
    "_rename": {"lib": "libc", "purpose": "rename/move file", "category": "file_io"},
    "_unlink": {"lib": "libc", "purpose": "remove file (delete)", "category": "file_io"},
    "_remove": {"lib": "libc", "purpose": "remove file or directory", "category": "file_io"},
    "_truncate": {"lib": "libc", "purpose": "truncate file by path", "category": "file_io"},
    "_ftruncate": {"lib": "libc", "purpose": "truncate file by fd", "category": "file_io"},

    # Symlinks / paths
    "_symlink": {"lib": "libc", "purpose": "create symbolic link", "category": "file_io"},
    "_readlink": {"lib": "libc", "purpose": "read symbolic link target", "category": "file_io"},
    "_realpath": {"lib": "libc", "purpose": "resolve absolute pathname", "category": "file_io"},

    # File control
    "_fcntl": {"lib": "libc", "purpose": "file descriptor control (lock/flags)", "category": "file_io"},
    "_ioctl": {"lib": "libc", "purpose": "device I/O control", "category": "file_io"},

    # Memory-mapped I/O
    "_mmap": {"lib": "libc", "purpose": "map file/device into memory", "category": "memory"},
    "_munmap": {"lib": "libc", "purpose": "unmap memory region", "category": "memory"},
    "_mprotect": {"lib": "libc", "purpose": "set memory region protection", "category": "memory"},
    "_msync": {"lib": "libc", "purpose": "sync memory-mapped file to disk", "category": "file_io"},
    "_mlock": {"lib": "libc", "purpose": "lock memory pages (prevent swap)", "category": "memory"},
    "_munlock": {"lib": "libc", "purpose": "unlock memory pages", "category": "memory"},

    # Pipe / dup
    "_dup": {"lib": "libc", "purpose": "duplicate file descriptor", "category": "file_io"},
    "_dup2": {"lib": "libc", "purpose": "duplicate fd to specific number", "category": "file_io"},
    "_pipe": {"lib": "libc", "purpose": "create unidirectional pipe", "category": "file_io"},
}


# ---------------------------------------------------------------------------
# process_signatures (40 entry) — Process yonetimi: fork/exec, signals, identity, posix_spawn, exit.
# Kaynak: signature_db.py _PROCESS_SIGNATURES.
# ---------------------------------------------------------------------------
_PROCESS_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Process creation
    "_fork": {"lib": "libc", "purpose": "create child process (copy)", "category": "process"},
    "_vfork": {"lib": "libc", "purpose": "create child (shared memory, deprecated)", "category": "process"},
    "_execve": {"lib": "libc", "purpose": "execute program (replace process image)", "category": "process"},
    "_execvp": {"lib": "libc", "purpose": "execute program (PATH search)", "category": "process"},
    "_execl": {"lib": "libc", "purpose": "execute program (variadic args)", "category": "process"},
    "_execlp": {"lib": "libc", "purpose": "execute program (PATH + variadic)", "category": "process"},

    # Process wait
    "_waitpid": {"lib": "libc", "purpose": "wait for child process", "category": "process"},
    "_wait": {"lib": "libc", "purpose": "wait for any child process", "category": "process"},
    "_wait4": {"lib": "libc", "purpose": "wait with resource usage", "category": "process"},
    "_waitid": {"lib": "libc", "purpose": "wait for child (extended)", "category": "process"},

    # Signals
    "_kill": {"lib": "libc", "purpose": "send signal to process", "category": "process"},
    "_raise": {"lib": "libc", "purpose": "send signal to self", "category": "process"},
    "_signal": {"lib": "libc", "purpose": "set signal handler (legacy)", "category": "process"},
    "_sigaction": {"lib": "libc", "purpose": "set signal handler (POSIX)", "category": "process"},
    "_sigprocmask": {"lib": "libc", "purpose": "block/unblock signals", "category": "process"},
    "_sigsuspend": {"lib": "libc", "purpose": "suspend until signal", "category": "process"},

    # Process identity
    "_getpid": {"lib": "libc", "purpose": "get process ID", "category": "process"},
    "_getppid": {"lib": "libc", "purpose": "get parent process ID", "category": "process"},
    "_getuid": {"lib": "libc", "purpose": "get real user ID", "category": "process"},
    "_geteuid": {"lib": "libc", "purpose": "get effective user ID", "category": "process"},
    "_getgid": {"lib": "libc", "purpose": "get real group ID", "category": "process"},
    "_getegid": {"lib": "libc", "purpose": "get effective group ID", "category": "process"},

    # Privilege management
    "_setuid": {"lib": "libc", "purpose": "set user ID (privilege change)", "category": "process"},
    "_setgid": {"lib": "libc", "purpose": "set group ID", "category": "process"},
    "_seteuid": {"lib": "libc", "purpose": "set effective user ID", "category": "process"},
    "_setegid": {"lib": "libc", "purpose": "set effective group ID", "category": "process"},

    # POSIX spawn
    "_posix_spawn": {"lib": "libc", "purpose": "spawn new process (POSIX)", "category": "process"},
    "_posix_spawnp": {"lib": "libc", "purpose": "spawn new process (PATH search)", "category": "process"},
    "_posix_spawn_file_actions_addopen": {"lib": "libc", "purpose": "posix_spawn file action: open", "category": "process"},

    # Shell / popen
    "_system": {"lib": "libc", "purpose": "execute shell command", "category": "process"},
    "_popen": {"lib": "libc", "purpose": "open pipe to shell command", "category": "process"},
    "_pclose": {"lib": "libc", "purpose": "close pipe to shell command", "category": "process"},

    # Process exit
    "__exit": {"lib": "libc", "purpose": "immediate process exit (no cleanup)", "category": "process"},
    "_exit": {"lib": "libc", "purpose": "terminate process with cleanup", "category": "process"},
    "_atexit": {"lib": "libc", "purpose": "register exit handler", "category": "process"},
    "_abort": {"lib": "libc", "purpose": "abort process (SIGABRT)", "category": "process"},

    # Session / process group
    "_setsid": {"lib": "libc", "purpose": "create new session (daemon)", "category": "process"},
    "_setpgid": {"lib": "libc", "purpose": "set process group ID", "category": "process"},
    "_getpgid": {"lib": "libc", "purpose": "get process group ID", "category": "process"},
    "_tcsetpgrp": {"lib": "libc", "purpose": "set foreground process group", "category": "process"},
}


# ---------------------------------------------------------------------------
# pthread_signatures (37 entry) — POSIX threads (pthread): yasam dongusu, mutex, rwlock, cond, TLS, semaphores.
# Kaynak: signature_db.py _PTHREAD_SIGNATURES.
# ---------------------------------------------------------------------------
_PTHREAD_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Thread lifecycle
    "_pthread_create": {"lib": "libpthread", "purpose": "create new thread", "category": "threading"},
    "_pthread_join": {"lib": "libpthread", "purpose": "wait for thread termination", "category": "threading"},
    "_pthread_detach": {"lib": "libpthread", "purpose": "detach thread (auto-cleanup)", "category": "threading"},
    "_pthread_exit": {"lib": "libpthread", "purpose": "terminate calling thread", "category": "threading"},

    # Mutex
    "_pthread_mutex_init": {"lib": "libpthread", "purpose": "initialize mutex", "category": "threading"},
    "_pthread_mutex_lock": {"lib": "libpthread", "purpose": "lock mutex (blocking)", "category": "threading"},
    "_pthread_mutex_trylock": {"lib": "libpthread", "purpose": "try lock mutex (non-blocking)", "category": "threading"},
    "_pthread_mutex_unlock": {"lib": "libpthread", "purpose": "unlock mutex", "category": "threading"},
    "_pthread_mutex_destroy": {"lib": "libpthread", "purpose": "destroy mutex", "category": "threading"},

    # Read-write lock
    "_pthread_rwlock_init": {"lib": "libpthread", "purpose": "initialize read-write lock", "category": "threading"},
    "_pthread_rwlock_rdlock": {"lib": "libpthread", "purpose": "acquire read lock", "category": "threading"},
    "_pthread_rwlock_wrlock": {"lib": "libpthread", "purpose": "acquire write lock", "category": "threading"},
    "_pthread_rwlock_unlock": {"lib": "libpthread", "purpose": "release read-write lock", "category": "threading"},
    "_pthread_rwlock_destroy": {"lib": "libpthread", "purpose": "destroy read-write lock", "category": "threading"},

    # Condition variable
    "_pthread_cond_init": {"lib": "libpthread", "purpose": "initialize condition variable", "category": "threading"},
    "_pthread_cond_wait": {"lib": "libpthread", "purpose": "wait on condition variable", "category": "threading"},
    "_pthread_cond_timedwait": {"lib": "libpthread", "purpose": "timed wait on condition variable", "category": "threading"},
    "_pthread_cond_signal": {"lib": "libpthread", "purpose": "signal one waiting thread", "category": "threading"},
    "_pthread_cond_broadcast": {"lib": "libpthread", "purpose": "signal all waiting threads", "category": "threading"},
    "_pthread_cond_destroy": {"lib": "libpthread", "purpose": "destroy condition variable", "category": "threading"},

    # Thread-local storage
    "_pthread_key_create": {"lib": "libpthread", "purpose": "create thread-local storage key", "category": "threading"},
    "_pthread_key_delete": {"lib": "libpthread", "purpose": "delete thread-local storage key", "category": "threading"},
    "_pthread_getspecific": {"lib": "libpthread", "purpose": "get thread-local value", "category": "threading"},
    "_pthread_setspecific": {"lib": "libpthread", "purpose": "set thread-local value", "category": "threading"},

    # Thread utility
    "_pthread_once": {"lib": "libpthread", "purpose": "one-time initialization", "category": "threading"},
    "_pthread_self": {"lib": "libpthread", "purpose": "get current thread ID", "category": "threading"},
    "_pthread_equal": {"lib": "libpthread", "purpose": "compare thread IDs", "category": "threading"},

    # Thread attributes
    "_pthread_attr_init": {"lib": "libpthread", "purpose": "initialize thread attributes", "category": "threading"},
    "_pthread_attr_destroy": {"lib": "libpthread", "purpose": "destroy thread attributes", "category": "threading"},
    "_pthread_attr_setdetachstate": {"lib": "libpthread", "purpose": "set thread detach state", "category": "threading"},
    "_pthread_attr_setstacksize": {"lib": "libpthread", "purpose": "set thread stack size", "category": "threading"},

    # POSIX semaphores
    "_sem_open": {"lib": "libpthread", "purpose": "open named semaphore", "category": "threading"},
    "_sem_close": {"lib": "libpthread", "purpose": "close named semaphore", "category": "threading"},
    "_sem_wait": {"lib": "libpthread", "purpose": "decrement semaphore (blocking)", "category": "threading"},
    "_sem_trywait": {"lib": "libpthread", "purpose": "try decrement semaphore (non-blocking)", "category": "threading"},
    "_sem_post": {"lib": "libpthread", "purpose": "increment semaphore (signal)", "category": "threading"},
    "_sem_unlink": {"lib": "libpthread", "purpose": "remove named semaphore", "category": "threading"},
}


# ---------------------------------------------------------------------------
# memory_signatures (27 entry) — Bellek yonetimi: malloc/free ailesi, Mach VM, mem ops (memcpy/memset/...).
# Kaynak: signature_db.py _MEMORY_SIGNATURES.
# ---------------------------------------------------------------------------
_MEMORY_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Standard C allocator
    "_malloc": {"lib": "libc", "purpose": "allocate heap memory", "category": "memory"},
    "_calloc": {"lib": "libc", "purpose": "allocate zeroed heap memory", "category": "memory"},
    "_realloc": {"lib": "libc", "purpose": "resize heap allocation", "category": "memory"},
    "_free": {"lib": "libc", "purpose": "free heap memory", "category": "memory"},
    "_posix_memalign": {"lib": "libc", "purpose": "aligned memory allocation (POSIX)", "category": "memory"},
    "_aligned_alloc": {"lib": "libc", "purpose": "aligned memory allocation (C11)", "category": "memory"},

    # Virtual memory (POSIX)
    "_madvise": {"lib": "libc", "purpose": "advise kernel on memory usage pattern", "category": "memory"},
    "_mincore": {"lib": "libc", "purpose": "check pages in core (resident)", "category": "memory"},

    # Legacy heap
    "_brk": {"lib": "libc", "purpose": "set data segment break", "category": "memory"},
    "_sbrk": {"lib": "libc", "purpose": "increment data segment break", "category": "memory"},

    # macOS Mach VM
    "_vm_allocate": {"lib": "libSystem", "purpose": "Mach VM region allocation", "category": "memory"},
    "_vm_deallocate": {"lib": "libSystem", "purpose": "Mach VM region deallocation", "category": "memory"},
    "_vm_protect": {"lib": "libSystem", "purpose": "Mach VM region protection change", "category": "memory"},
    "_vm_read": {"lib": "libSystem", "purpose": "Mach VM read from task", "category": "memory"},
    "_vm_write": {"lib": "libSystem", "purpose": "Mach VM write to task", "category": "memory"},
    "_mach_vm_allocate": {"lib": "libSystem", "purpose": "Mach VM allocate (64-bit)", "category": "memory"},
    "_mach_vm_deallocate": {"lib": "libSystem", "purpose": "Mach VM deallocate (64-bit)", "category": "memory"},
    "_mach_vm_protect": {"lib": "libSystem", "purpose": "Mach VM protect (64-bit)", "category": "memory"},

    # Legacy aligned alloc
    "_valloc": {"lib": "libc", "purpose": "page-aligned allocation (deprecated)", "category": "memory"},
    "_memalign": {"lib": "libc", "purpose": "aligned allocation (legacy)", "category": "memory"},

    # Memory operations
    "_memcpy": {"lib": "libc", "purpose": "copy memory block (non-overlapping)", "category": "memory"},
    "_memmove": {"lib": "libc", "purpose": "copy memory block (overlap-safe)", "category": "memory"},
    "_memset": {"lib": "libc", "purpose": "fill memory block with byte", "category": "memory"},
    "_memcmp": {"lib": "libc", "purpose": "compare memory blocks", "category": "memory"},
    "_memchr": {"lib": "libc", "purpose": "search byte in memory", "category": "memory"},
    "_bzero": {"lib": "libc", "purpose": "zero memory block (BSD legacy)", "category": "memory"},
    "_bcopy": {"lib": "libc", "purpose": "copy memory block (BSD legacy)", "category": "memory"},
}


# ---------------------------------------------------------------------------
# string_stdlib_signatures (42 entry) — libc string + stdlib: str* aile, formatted I/O, atoi/strtol, qsort, rand, env.
# Kaynak: signature_db.py _STRING_STDLIB_SIGNATURES.
# ---------------------------------------------------------------------------
_STRING_STDLIB_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # String operations
    "_strlen": {"lib": "libc", "purpose": "compute string length", "category": "string"},
    "_strcmp": {"lib": "libc", "purpose": "compare strings", "category": "string"},
    "_strncmp": {"lib": "libc", "purpose": "compare strings (bounded)", "category": "string"},
    "_strcpy": {"lib": "libc", "purpose": "copy string (unsafe)", "category": "string"},
    "_strncpy": {"lib": "libc", "purpose": "copy string (bounded)", "category": "string"},
    "_strcat": {"lib": "libc", "purpose": "concatenate strings (unsafe)", "category": "string"},
    "_strncat": {"lib": "libc", "purpose": "concatenate strings (bounded)", "category": "string"},
    "_strstr": {"lib": "libc", "purpose": "find substring", "category": "string"},
    "_strchr": {"lib": "libc", "purpose": "find character in string", "category": "string"},
    "_strrchr": {"lib": "libc", "purpose": "find last character in string", "category": "string"},
    "_strdup": {"lib": "libc", "purpose": "duplicate string (heap alloc)", "category": "string"},
    "_strndup": {"lib": "libc", "purpose": "duplicate string (bounded, heap alloc)", "category": "string"},
    "_strtok": {"lib": "libc", "purpose": "tokenize string (not thread-safe)", "category": "string"},
    "_strtok_r": {"lib": "libc", "purpose": "tokenize string (reentrant)", "category": "string"},

    # Formatted I/O
    "_sprintf": {"lib": "libc", "purpose": "formatted string write (unsafe)", "category": "string"},
    "_snprintf": {"lib": "libc", "purpose": "formatted string write (bounded)", "category": "string"},
    "_sscanf": {"lib": "libc", "purpose": "formatted string parse", "category": "string"},
    "_printf": {"lib": "libc", "purpose": "formatted stdout print", "category": "string"},
    "_puts": {"lib": "libc", "purpose": "write string to stdout", "category": "string"},
    "_putchar": {"lib": "libc", "purpose": "write character to stdout", "category": "string"},

    # String-to-number conversion
    "_atoi": {"lib": "libc", "purpose": "string to int (no error check)", "category": "string"},
    "_atol": {"lib": "libc", "purpose": "string to long (no error check)", "category": "string"},
    "_atof": {"lib": "libc", "purpose": "string to double (no error check)", "category": "string"},
    "_strtol": {"lib": "libc", "purpose": "string to long (with error check)", "category": "string"},
    "_strtoul": {"lib": "libc", "purpose": "string to unsigned long", "category": "string"},
    "_strtod": {"lib": "libc", "purpose": "string to double (with error check)", "category": "string"},
    "_strtoll": {"lib": "libc", "purpose": "string to long long", "category": "string"},
    "_strtoull": {"lib": "libc", "purpose": "string to unsigned long long", "category": "string"},

    # Sorting / searching
    "_qsort": {"lib": "libc", "purpose": "quicksort array", "category": "stdlib"},
    "_bsearch": {"lib": "libc", "purpose": "binary search sorted array", "category": "stdlib"},
    "_abs": {"lib": "libc", "purpose": "absolute value (int)", "category": "stdlib"},
    "_labs": {"lib": "libc", "purpose": "absolute value (long)", "category": "stdlib"},

    # Random number generation
    "_rand": {"lib": "libc", "purpose": "pseudo-random number (not crypto-safe)", "category": "stdlib"},
    "_srand": {"lib": "libc", "purpose": "seed pseudo-random generator", "category": "stdlib"},
    "_random": {"lib": "libc", "purpose": "better pseudo-random (BSD)", "category": "stdlib"},
    "_srandom": {"lib": "libc", "purpose": "seed BSD random generator", "category": "stdlib"},
    "_arc4random": {"lib": "libc", "purpose": "crypto-quality random number", "category": "stdlib"},
    "_arc4random_uniform": {"lib": "libc", "purpose": "crypto-quality random in range", "category": "stdlib"},

    # Environment
    "_getenv": {"lib": "libc", "purpose": "get environment variable", "category": "stdlib"},
    "_setenv": {"lib": "libc", "purpose": "set environment variable", "category": "stdlib"},
    "_unsetenv": {"lib": "libc", "purpose": "remove environment variable", "category": "stdlib"},
    "_putenv": {"lib": "libc", "purpose": "set environment variable (legacy)", "category": "stdlib"},
}


# ---------------------------------------------------------------------------
# time_signatures (16 entry) — Zaman: time/clock_gettime, conversion, formatlama, sleep, Mach time.
# Kaynak: signature_db.py _TIME_SIGNATURES.
# ---------------------------------------------------------------------------
_TIME_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Getting time
    "_time": {"lib": "libc", "purpose": "get calendar time (seconds)", "category": "time"},
    "_gettimeofday": {"lib": "libc", "purpose": "get time with microseconds", "category": "time"},
    "_clock_gettime": {"lib": "libc", "purpose": "get time with nanoseconds (POSIX)", "category": "time"},
    "_clock_getres": {"lib": "libc", "purpose": "get clock resolution", "category": "time"},

    # Time conversion
    "_localtime": {"lib": "libc", "purpose": "convert to local time struct", "category": "time"},
    "_localtime_r": {"lib": "libc", "purpose": "convert to local time (reentrant)", "category": "time"},
    "_gmtime": {"lib": "libc", "purpose": "convert to UTC time struct", "category": "time"},
    "_gmtime_r": {"lib": "libc", "purpose": "convert to UTC time (reentrant)", "category": "time"},
    "_mktime": {"lib": "libc", "purpose": "convert time struct to calendar time", "category": "time"},

    # Time formatting
    "_strftime": {"lib": "libc", "purpose": "format time as string", "category": "time"},
    "_strptime": {"lib": "libc", "purpose": "parse time from string", "category": "time"},

    # Sleep / delay
    "_nanosleep": {"lib": "libc", "purpose": "sleep with nanosecond precision", "category": "time"},
    "_usleep": {"lib": "libc", "purpose": "sleep with microsecond precision", "category": "time"},
    "_sleep": {"lib": "libc", "purpose": "sleep with second precision", "category": "time"},

    # macOS Mach time
    "_mach_absolute_time": {"lib": "libSystem", "purpose": "high-resolution monotonic time (macOS)", "category": "time"},
    "_mach_timebase_info": {"lib": "libSystem", "purpose": "Mach time to nanoseconds conversion factor", "category": "time"},
}


# ---------------------------------------------------------------------------
# dynload_signatures (10 entry) — Dinamik yukleme: dlopen/dlsym/dladdr ve macOS legacy NSModule/dyld.
# Kaynak: signature_db.py _DYNLOAD_SIGNATURES.
# ---------------------------------------------------------------------------
_DYNLOAD_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # POSIX dynamic loading
    "_dlopen": {"lib": "libdl", "purpose": "load shared library at runtime", "category": "dynload"},
    "_dlclose": {"lib": "libdl", "purpose": "unload shared library", "category": "dynload"},
    "_dlsym": {"lib": "libdl", "purpose": "lookup symbol in shared library", "category": "dynload"},
    "_dlerror": {"lib": "libdl", "purpose": "get dynamic loader error string", "category": "dynload"},
    "_dladdr": {"lib": "libdl", "purpose": "resolve address to symbol info", "category": "dynload"},

    # macOS legacy NSModule
    "_NSLookupSymbolInModule": {"lib": "libSystem", "purpose": "lookup symbol in NSModule (legacy)", "category": "dynload"},
    "_NSAddressOfSymbol": {"lib": "libSystem", "purpose": "get address of NSSymbol (legacy)", "category": "dynload"},

    # macOS dyld
    "__dyld_get_image_name": {"lib": "libdyld", "purpose": "get loaded image path by index", "category": "dynload"},
    "__dyld_image_count": {"lib": "libdyld", "purpose": "get number of loaded images", "category": "dynload"},
    "__dyld_get_image_header": {"lib": "libdyld", "purpose": "get Mach-O header of loaded image", "category": "dynload"},
}


# ---------------------------------------------------------------------------
# error_locale_misc_signatures (18 entry) — Hata mesaji, locale, ctype, assert, syslog (legacy), sysctl.
# Kaynak: signature_db.py _ERROR_LOCALE_MISC_SIGNATURES.
# ---------------------------------------------------------------------------
_ERROR_LOCALE_MISC_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Error reporting
    "_strerror": {"lib": "libc", "purpose": "convert errno to error string", "category": "error"},
    "_strerror_r": {"lib": "libc", "purpose": "convert errno to error string (reentrant)", "category": "error"},
    "_perror": {"lib": "libc", "purpose": "print error message to stderr", "category": "error"},

    # Locale
    "_setlocale": {"lib": "libc", "purpose": "set program locale", "category": "locale"},
    "_localeconv": {"lib": "libc", "purpose": "get locale numeric formatting", "category": "locale"},

    # Character classification
    "_isalpha": {"lib": "libc", "purpose": "test for alphabetic character", "category": "ctype"},
    "_isdigit": {"lib": "libc", "purpose": "test for decimal digit", "category": "ctype"},
    "_isalnum": {"lib": "libc", "purpose": "test for alphanumeric character", "category": "ctype"},
    "_isspace": {"lib": "libc", "purpose": "test for whitespace character", "category": "ctype"},
    "_toupper": {"lib": "libc", "purpose": "convert to uppercase", "category": "ctype"},
    "_tolower": {"lib": "libc", "purpose": "convert to lowercase", "category": "ctype"},

    # Assertions
    "_assert": {"lib": "libc", "purpose": "runtime assertion check", "category": "error"},
    "___assert_rtn": {"lib": "libc", "purpose": "macOS assertion failure handler", "category": "error"},

    # Syslog
    "_syslog": {"lib": "libc", "purpose": "write to system log", "category": "logging"},
    "_openlog": {"lib": "libc", "purpose": "open syslog connection", "category": "logging"},
    "_closelog": {"lib": "libc", "purpose": "close syslog connection", "category": "logging"},

    # System info
    "_sysctl": {"lib": "libc", "purpose": "get/set kernel parameters", "category": "system"},
    "_sysctlbyname": {"lib": "libc", "purpose": "get/set kernel parameters by name", "category": "system"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category("posix_system") bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur.
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "posix_file_io_signatures": _POSIX_FILE_IO_SIGNATURES_DATA,
    "process_signatures": _PROCESS_SIGNATURES_DATA,
    "pthread_signatures": _PTHREAD_SIGNATURES_DATA,
    "memory_signatures": _MEMORY_SIGNATURES_DATA,
    "string_stdlib_signatures": _STRING_STDLIB_SIGNATURES_DATA,
    "time_signatures": _TIME_SIGNATURES_DATA,
    "dynload_signatures": _DYNLOAD_SIGNATURES_DATA,
    "error_locale_misc_signatures": _ERROR_LOCALE_MISC_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
