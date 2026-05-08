"""Linux/system signatures — sig_db v1.13 Dalga 2 migrasyonu (ADR 0007 A2).

Kaynak: karadul/analyzers/signature_db.py
  - _LINUX_SYSCALL_SIGNATURES    -> linux_syscall_signatures
  - _LINUX_SYSCALL_EXT_SIGNATURES    -> linux_syscall_ext_signatures
  - _LIBC_EXT_SIGNATURES    -> libc_ext_signatures

Toplam: 399 signature (3 dict).

ADR 0007/0008 Tip A yumusak override pattern'i (POSIX/system kategorisiyle
ozdes): signature_db.py'de orijinal dict govdeleri SILINMEDI; runtime'da bu
modulden gelen veriyle yeniden baglanir. Rollback icin override blogu
silinince (try/except ImportError) eski inline veri otomatik geri devreye
girer. Birebir parite garanti (AST literal_eval; bkz.
tests/test_sigdb_linux_system_migration.py).

Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur:
  ``linux_syscall_signatures``    <-> ``_LINUX_SYSCALL_SIGNATURES``
  ``linux_syscall_ext_signatures``    <-> ``_LINUX_SYSCALL_EXT_SIGNATURES``
  ``libc_ext_signatures``    <-> ``_LIBC_EXT_SIGNATURES``

NOT: ``_POSIX_NETWORKING_SIGNATURES`` (epoll, kqueue, socket icermesine
ragmen) bu modulde TASINMADI — zaten ``sigdb_builtin/network.py`` icinde
override ediliyor (signature_db.py satir ~6537). Cifte override cakismasini
onlemek icin network kategorisinde tutuldu. Bu modul yalnizca syscall
wrapper + libc-ext kapsamini eziyor.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# linux_syscall_signatures (36 entry) — Linux syscall ailesi: epoll, eventfd, signalfd, timerfd, prctl, futex, capability, mount/namespace.
# Kaynak: signature_db.py _LINUX_SYSCALL_SIGNATURES.
# ---------------------------------------------------------------------------
_LINUX_SYSCALL_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # epoll
    "epoll_create": {"lib": "libc", "purpose": "create epoll instance (deprecated)", "category": "linux_io"},
    "epoll_create1": {"lib": "libc", "purpose": "create epoll instance with flags", "category": "linux_io"},
    "epoll_ctl": {"lib": "libc", "purpose": "add/modify/remove epoll interest list entry", "category": "linux_io"},
    "epoll_wait": {"lib": "libc", "purpose": "wait for I/O events on epoll instance", "category": "linux_io"},

    # inotify
    "inotify_init": {"lib": "libc", "purpose": "create inotify instance (deprecated)", "category": "linux_io"},
    "inotify_init1": {"lib": "libc", "purpose": "create inotify instance with flags", "category": "linux_io"},
    "inotify_add_watch": {"lib": "libc", "purpose": "add watch to inotify instance", "category": "linux_io"},
    "inotify_rm_watch": {"lib": "libc", "purpose": "remove watch from inotify instance", "category": "linux_io"},

    # eventfd
    "eventfd": {"lib": "libc", "purpose": "create eventfd file descriptor", "category": "linux_io"},
    "eventfd_read": {"lib": "libc", "purpose": "read eventfd counter value", "category": "linux_io"},
    "eventfd_write": {"lib": "libc", "purpose": "write to eventfd counter", "category": "linux_io"},

    # timerfd
    "timerfd_create": {"lib": "libc", "purpose": "create timerfd file descriptor", "category": "linux_io"},
    "timerfd_settime": {"lib": "libc", "purpose": "arm/disarm timerfd timer", "category": "linux_io"},
    "timerfd_gettime": {"lib": "libc", "purpose": "get timerfd current timer value", "category": "linux_io"},

    # signalfd
    "signalfd": {"lib": "libc", "purpose": "create file descriptor for signal delivery", "category": "linux_io"},
    "signalfd4": {"lib": "libc", "purpose": "create signalfd with flags (internal)", "category": "linux_io"},

    # Advanced socket
    "accept4": {"lib": "libc", "purpose": "accept connection with flags (SOCK_NONBLOCK etc)", "category": "linux_network"},
    "recvmmsg": {"lib": "libc", "purpose": "receive multiple messages in single syscall", "category": "linux_network"},
    "sendmmsg": {"lib": "libc", "purpose": "send multiple messages in single syscall", "category": "linux_network"},

    # Splice / zero-copy
    "splice": {"lib": "libc", "purpose": "zero-copy data transfer between fds via pipe", "category": "linux_io"},
    "tee": {"lib": "libc", "purpose": "duplicate pipe content without consuming", "category": "linux_io"},
    "vmsplice": {"lib": "libc", "purpose": "splice user pages into pipe", "category": "linux_io"},

    # Security / sandboxing
    "prctl": {"lib": "libc", "purpose": "process control operations", "category": "linux_security"},
    "seccomp": {"lib": "libc", "purpose": "operate on seccomp BPF filters", "category": "linux_security"},

    # Namespaces / clone
    "clone": {"lib": "libc", "purpose": "create child process (low-level fork with flags)", "category": "linux_process"},
    "clone3": {"lib": "libc", "purpose": "create child process (extensible clone)", "category": "linux_process"},
    "unshare": {"lib": "libc", "purpose": "disassociate parts of process execution context", "category": "linux_process"},
    "setns": {"lib": "libc", "purpose": "reassociate thread with a namespace", "category": "linux_process"},

    # io_uring
    "io_uring_setup": {"lib": "libc", "purpose": "setup io_uring submission/completion queues", "category": "linux_io"},
    "io_uring_enter": {"lib": "libc", "purpose": "submit and/or wait for io_uring completions", "category": "linux_io"},
    "io_uring_register": {"lib": "libc", "purpose": "register resources with io_uring instance", "category": "linux_io"},

    # Misc modern syscalls
    "getrandom": {"lib": "libc", "purpose": "obtain random bytes from kernel", "category": "linux_security"},
    "memfd_create": {"lib": "libc", "purpose": "create anonymous file in memory", "category": "linux_io"},
    "userfaultfd": {"lib": "libc", "purpose": "create userfaultfd for userspace page fault handling", "category": "linux_io"},

    # fanotify
    "fanotify_init": {"lib": "libc", "purpose": "create fanotify notification group", "category": "linux_io"},
    "fanotify_mark": {"lib": "libc", "purpose": "add/remove/modify fanotify mark", "category": "linux_io"},
}


# ---------------------------------------------------------------------------
# linux_syscall_ext_signatures (213 entry) — Genisletilmis Linux syscall'lari: glibc/musl POSIX wrapper kapsami (open/read/...), inotify, sendfile/splice, futex extra, namespaces.
# Kaynak: signature_db.py _LINUX_SYSCALL_EXT_SIGNATURES.
# ---------------------------------------------------------------------------
_LINUX_SYSCALL_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- Core file I/O syscalls ---
    "read": {"lib": "libc", "purpose": "read bytes from file descriptor", "category": "linux_io"},
    "write": {"lib": "libc", "purpose": "write bytes to file descriptor", "category": "linux_io"},
    "open": {"lib": "libc", "purpose": "open file and return fd", "category": "linux_io"},
    "close": {"lib": "libc", "purpose": "close file descriptor", "category": "linux_io"},
    "lseek": {"lib": "libc", "purpose": "reposition file offset", "category": "linux_io"},
    "pread": {"lib": "libc", "purpose": "read from fd at offset without seeking", "category": "linux_io"},
    "pread64": {"lib": "libc", "purpose": "read from fd at 64-bit offset", "category": "linux_io"},
    "pwrite": {"lib": "libc", "purpose": "write to fd at offset without seeking", "category": "linux_io"},
    "pwrite64": {"lib": "libc", "purpose": "write to fd at 64-bit offset", "category": "linux_io"},
    "readv": {"lib": "libc", "purpose": "scatter read from fd into multiple buffers", "category": "linux_io"},
    "writev": {"lib": "libc", "purpose": "gather write to fd from multiple buffers", "category": "linux_io"},
    "preadv": {"lib": "libc", "purpose": "scatter read at offset", "category": "linux_io"},
    "pwritev": {"lib": "libc", "purpose": "gather write at offset", "category": "linux_io"},
    "preadv2": {"lib": "libc", "purpose": "scatter read with flags", "category": "linux_io"},
    "pwritev2": {"lib": "libc", "purpose": "gather write with flags", "category": "linux_io"},
    "openat": {"lib": "libc", "purpose": "open file relative to directory fd", "category": "linux_io"},
    "openat2": {"lib": "libc", "purpose": "open file with extended flags (resolve restrictions)", "category": "linux_io"},
    "creat": {"lib": "libc", "purpose": "create file (equivalent to open with O_CREAT|O_TRUNC)", "category": "linux_io"},

    # --- File metadata syscalls ---
    "stat": {"lib": "libc", "purpose": "get file status by path", "category": "linux_fs"},
    "fstat": {"lib": "libc", "purpose": "get file status by fd", "category": "linux_fs"},
    "lstat": {"lib": "libc", "purpose": "get file status (no symlink follow)", "category": "linux_fs"},
    "stat64": {"lib": "libc", "purpose": "get file status (64-bit)", "category": "linux_fs"},
    "fstat64": {"lib": "libc", "purpose": "get file status by fd (64-bit)", "category": "linux_fs"},
    "lstat64": {"lib": "libc", "purpose": "get file status no follow (64-bit)", "category": "linux_fs"},
    "statx": {"lib": "libc", "purpose": "extended file status (birth time, mount id)", "category": "linux_fs"},
    "fstatat": {"lib": "libc", "purpose": "get file status relative to dir fd", "category": "linux_fs"},
    "newfstatat": {"lib": "libc", "purpose": "get file status relative to dir fd (new)", "category": "linux_fs"},
    "access": {"lib": "libc", "purpose": "check file access permissions", "category": "linux_fs"},
    "faccessat": {"lib": "libc", "purpose": "check file access relative to dir fd", "category": "linux_fs"},
    "faccessat2": {"lib": "libc", "purpose": "check file access with flags", "category": "linux_fs"},

    # --- Directory operations ---
    "mkdir": {"lib": "libc", "purpose": "create directory", "category": "linux_fs"},
    "mkdirat": {"lib": "libc", "purpose": "create directory relative to dir fd", "category": "linux_fs"},
    "rmdir": {"lib": "libc", "purpose": "remove empty directory", "category": "linux_fs"},
    "getcwd": {"lib": "libc", "purpose": "get current working directory", "category": "linux_fs"},
    "chdir": {"lib": "libc", "purpose": "change working directory", "category": "linux_fs"},
    "fchdir": {"lib": "libc", "purpose": "change working directory by fd", "category": "linux_fs"},
    "chroot": {"lib": "libc", "purpose": "change root directory", "category": "linux_fs"},
    "getdents": {"lib": "libc", "purpose": "get directory entries", "category": "linux_fs"},
    "getdents64": {"lib": "libc", "purpose": "get directory entries (64-bit)", "category": "linux_fs"},

    # --- File manipulation ---
    "unlink": {"lib": "libc", "purpose": "remove file or directory entry", "category": "linux_fs"},
    "unlinkat": {"lib": "libc", "purpose": "remove file relative to dir fd", "category": "linux_fs"},
    "rename": {"lib": "libc", "purpose": "rename file or directory", "category": "linux_fs"},
    "renameat": {"lib": "libc", "purpose": "rename relative to dir fds", "category": "linux_fs"},
    "renameat2": {"lib": "libc", "purpose": "rename with flags (RENAME_NOREPLACE etc)", "category": "linux_fs"},
    "link": {"lib": "libc", "purpose": "create hard link", "category": "linux_fs"},
    "linkat": {"lib": "libc", "purpose": "create hard link relative to dir fds", "category": "linux_fs"},
    "symlink": {"lib": "libc", "purpose": "create symbolic link", "category": "linux_fs"},
    "symlinkat": {"lib": "libc", "purpose": "create symbolic link relative to dir fd", "category": "linux_fs"},
    "readlink": {"lib": "libc", "purpose": "read symbolic link target", "category": "linux_fs"},
    "readlinkat": {"lib": "libc", "purpose": "read symlink target relative to dir fd", "category": "linux_fs"},
    "truncate": {"lib": "libc", "purpose": "truncate file to specified length", "category": "linux_fs"},
    "ftruncate": {"lib": "libc", "purpose": "truncate file by fd to specified length", "category": "linux_fs"},
    "fallocate": {"lib": "libc", "purpose": "preallocate or deallocate file space", "category": "linux_fs"},
    "copy_file_range": {"lib": "libc", "purpose": "server-side file copy (zero-copy)", "category": "linux_fs"},

    # --- Permission/ownership ---
    "chmod": {"lib": "libc", "purpose": "change file permission bits", "category": "linux_fs"},
    "fchmod": {"lib": "libc", "purpose": "change file permissions by fd", "category": "linux_fs"},
    "fchmodat": {"lib": "libc", "purpose": "change permissions relative to dir fd", "category": "linux_fs"},
    "chown": {"lib": "libc", "purpose": "change file owner and group", "category": "linux_fs"},
    "fchown": {"lib": "libc", "purpose": "change owner/group by fd", "category": "linux_fs"},
    "fchownat": {"lib": "libc", "purpose": "change owner/group relative to dir fd", "category": "linux_fs"},
    "lchown": {"lib": "libc", "purpose": "change symlink owner/group (no follow)", "category": "linux_fs"},
    "umask": {"lib": "libc", "purpose": "set file mode creation mask", "category": "linux_fs"},

    # --- Memory management ---
    "mmap": {"lib": "libc", "purpose": "map files or devices into memory", "category": "linux_memory"},
    "mmap2": {"lib": "libc", "purpose": "map files into memory (page-aligned offset)", "category": "linux_memory"},
    "munmap": {"lib": "libc", "purpose": "unmap pages of memory", "category": "linux_memory"},
    "mprotect": {"lib": "libc", "purpose": "set protection on memory region", "category": "linux_memory"},
    "mlock": {"lib": "libc", "purpose": "lock pages in memory (prevent swap)", "category": "linux_memory"},
    "mlock2": {"lib": "libc", "purpose": "lock pages with flags", "category": "linux_memory"},
    "munlock": {"lib": "libc", "purpose": "unlock pages allowing swap", "category": "linux_memory"},
    "mlockall": {"lib": "libc", "purpose": "lock all process pages in memory", "category": "linux_memory"},
    "munlockall": {"lib": "libc", "purpose": "unlock all process pages", "category": "linux_memory"},
    "mremap": {"lib": "libc", "purpose": "remap virtual memory address", "category": "linux_memory"},
    "msync": {"lib": "libc", "purpose": "synchronize memory-mapped file to disk", "category": "linux_memory"},
    "madvise": {"lib": "libc", "purpose": "advise kernel about memory usage patterns", "category": "linux_memory"},
    "mincore": {"lib": "libc", "purpose": "determine if pages are resident in memory", "category": "linux_memory"},
    "brk": {"lib": "libc", "purpose": "change data segment size (program break)", "category": "linux_memory"},
    "sbrk": {"lib": "libc", "purpose": "increment program break (data segment)", "category": "linux_memory"},

    # --- Process management ---
    "fork": {"lib": "libc", "purpose": "create child process (copy-on-write)", "category": "linux_process"},
    "vfork": {"lib": "libc", "purpose": "create child process (shared memory, deprecated)", "category": "linux_process"},
    "execve": {"lib": "libc", "purpose": "execute program replacing current process", "category": "linux_process"},
    "execvp": {"lib": "libc", "purpose": "execute program with PATH search", "category": "linux_process"},
    "execvpe": {"lib": "libc", "purpose": "execute program with PATH and custom env", "category": "linux_process"},
    "execl": {"lib": "libc", "purpose": "execute program with variadic args", "category": "linux_process"},
    "execlp": {"lib": "libc", "purpose": "execute program with PATH and variadic args", "category": "linux_process"},
    "execle": {"lib": "libc", "purpose": "execute program with variadic args and env", "category": "linux_process"},
    "wait": {"lib": "libc", "purpose": "wait for any child process to terminate", "category": "linux_process"},
    "waitpid": {"lib": "libc", "purpose": "wait for specific child process", "category": "linux_process"},
    "wait4": {"lib": "libc", "purpose": "wait for child with resource usage info", "category": "linux_process"},
    "waitid": {"lib": "libc", "purpose": "wait for child process state change", "category": "linux_process"},
    "getpid": {"lib": "libc", "purpose": "get process ID", "category": "linux_process"},
    "getppid": {"lib": "libc", "purpose": "get parent process ID", "category": "linux_process"},
    "getpgid": {"lib": "libc", "purpose": "get process group ID", "category": "linux_process"},
    "setpgid": {"lib": "libc", "purpose": "set process group ID", "category": "linux_process"},
    "getsid": {"lib": "libc", "purpose": "get session ID", "category": "linux_process"},
    "setsid": {"lib": "libc", "purpose": "create new session", "category": "linux_process"},
    "getuid": {"lib": "libc", "purpose": "get real user ID", "category": "linux_process"},
    "geteuid": {"lib": "libc", "purpose": "get effective user ID", "category": "linux_process"},
    "getgid": {"lib": "libc", "purpose": "get real group ID", "category": "linux_process"},
    "getegid": {"lib": "libc", "purpose": "get effective group ID", "category": "linux_process"},
    "setuid": {"lib": "libc", "purpose": "set real user ID", "category": "linux_process"},
    "seteuid": {"lib": "libc", "purpose": "set effective user ID", "category": "linux_process"},
    "setgid": {"lib": "libc", "purpose": "set real group ID", "category": "linux_process"},
    "setegid": {"lib": "libc", "purpose": "set effective group ID", "category": "linux_process"},
    "setreuid": {"lib": "libc", "purpose": "set real and effective user IDs", "category": "linux_process"},
    "setregid": {"lib": "libc", "purpose": "set real and effective group IDs", "category": "linux_process"},
    "setresuid": {"lib": "libc", "purpose": "set real, effective, and saved user IDs", "category": "linux_process"},
    "setresgid": {"lib": "libc", "purpose": "set real, effective, and saved group IDs", "category": "linux_process"},
    "getresuid": {"lib": "libc", "purpose": "get real, effective, and saved user IDs", "category": "linux_process"},
    "getresgid": {"lib": "libc", "purpose": "get real, effective, and saved group IDs", "category": "linux_process"},
    "getgroups": {"lib": "libc", "purpose": "get supplementary group IDs", "category": "linux_process"},
    "setgroups": {"lib": "libc", "purpose": "set supplementary group IDs", "category": "linux_process"},

    # --- Signal handling ---
    "kill": {"lib": "libc", "purpose": "send signal to process or process group", "category": "linux_signal"},
    "tgkill": {"lib": "libc", "purpose": "send signal to specific thread", "category": "linux_signal"},
    "tkill": {"lib": "libc", "purpose": "send signal to thread (deprecated, use tgkill)", "category": "linux_signal"},
    "sigaction": {"lib": "libc", "purpose": "examine and change signal action", "category": "linux_signal"},
    "rt_sigaction": {"lib": "libc", "purpose": "examine/change signal action (realtime)", "category": "linux_signal"},
    "sigprocmask": {"lib": "libc", "purpose": "examine/change blocked signals", "category": "linux_signal"},
    "rt_sigprocmask": {"lib": "libc", "purpose": "examine/change blocked signals (realtime)", "category": "linux_signal"},
    "sigpending": {"lib": "libc", "purpose": "examine pending signals", "category": "linux_signal"},
    "sigsuspend": {"lib": "libc", "purpose": "wait for signal with mask", "category": "linux_signal"},
    "sigwait": {"lib": "libc", "purpose": "synchronously wait for signal", "category": "linux_signal"},
    "sigwaitinfo": {"lib": "libc", "purpose": "synchronously wait for signal with info", "category": "linux_signal"},
    "sigtimedwait": {"lib": "libc", "purpose": "synchronously wait for signal with timeout", "category": "linux_signal"},
    "raise": {"lib": "libc", "purpose": "send signal to calling thread", "category": "linux_signal"},
    "alarm": {"lib": "libc", "purpose": "set alarm clock for SIGALRM delivery", "category": "linux_signal"},
    "pause": {"lib": "libc", "purpose": "wait for signal", "category": "linux_signal"},

    # --- Socket syscalls ---
    "socket": {"lib": "libc", "purpose": "create network socket endpoint", "category": "linux_network"},
    "bind": {"lib": "libc", "purpose": "bind socket to address", "category": "linux_network"},
    "listen": {"lib": "libc", "purpose": "mark socket as passive (server)", "category": "linux_network"},
    "accept": {"lib": "libc", "purpose": "accept incoming connection on socket", "category": "linux_network"},
    "connect": {"lib": "libc", "purpose": "initiate connection on socket", "category": "linux_network"},
    "sendmsg": {"lib": "libc", "purpose": "send message on socket with ancillary data", "category": "linux_network"},
    "recvmsg": {"lib": "libc", "purpose": "receive message from socket with ancillary data", "category": "linux_network"},
    "shutdown": {"lib": "libc", "purpose": "shut down part of full-duplex connection", "category": "linux_network"},
    "getsockopt": {"lib": "libc", "purpose": "get socket option value", "category": "linux_network"},
    "setsockopt": {"lib": "libc", "purpose": "set socket option value", "category": "linux_network"},
    "getsockname": {"lib": "libc", "purpose": "get socket local address", "category": "linux_network"},
    "getpeername": {"lib": "libc", "purpose": "get socket peer address", "category": "linux_network"},
    "socketpair": {"lib": "libc", "purpose": "create pair of connected sockets", "category": "linux_network"},

    # --- Pipe/dup ---
    "pipe": {"lib": "libc", "purpose": "create unidirectional pipe", "category": "linux_io"},
    "pipe2": {"lib": "libc", "purpose": "create pipe with flags (O_CLOEXEC, O_NONBLOCK)", "category": "linux_io"},
    "dup": {"lib": "libc", "purpose": "duplicate file descriptor", "category": "linux_io"},
    "dup2": {"lib": "libc", "purpose": "duplicate fd to specific number", "category": "linux_io"},
    "dup3": {"lib": "libc", "purpose": "duplicate fd with flags", "category": "linux_io"},

    # --- Polling/select ---
    "poll": {"lib": "libc", "purpose": "wait for events on file descriptors", "category": "linux_io"},
    "ppoll": {"lib": "libc", "purpose": "poll with signal mask and timespec", "category": "linux_io"},
    "pselect": {"lib": "libc", "purpose": "synchronous I/O multiplexing with sigmask", "category": "linux_io"},

    # --- ioctl/fcntl ---
    "ioctl": {"lib": "libc", "purpose": "device-specific I/O control", "category": "linux_io"},
    "fcntl": {"lib": "libc", "purpose": "file descriptor control operations", "category": "linux_io"},
    "fcntl64": {"lib": "libc", "purpose": "file descriptor control (64-bit)", "category": "linux_io"},

    # --- Time ---
    "gettimeofday": {"lib": "libc", "purpose": "get current time (microsecond precision)", "category": "linux_time"},
    "settimeofday": {"lib": "libc", "purpose": "set current time", "category": "linux_time"},
    "clock_gettime": {"lib": "libc", "purpose": "get clock time (nanosecond precision)", "category": "linux_time"},
    "clock_settime": {"lib": "libc", "purpose": "set clock time", "category": "linux_time"},
    "clock_getres": {"lib": "libc", "purpose": "get clock resolution", "category": "linux_time"},
    "clock_nanosleep": {"lib": "libc", "purpose": "high-resolution sleep with clock ID", "category": "linux_time"},
    "nanosleep": {"lib": "libc", "purpose": "high-resolution sleep", "category": "linux_time"},
    "time": {"lib": "libc", "purpose": "get time in seconds since epoch", "category": "linux_time"},
    "times": {"lib": "libc", "purpose": "get process/children CPU times", "category": "linux_time"},
    "timer_create": {"lib": "libc", "purpose": "create POSIX per-process timer", "category": "linux_time"},
    "timer_settime": {"lib": "libc", "purpose": "arm/disarm POSIX timer", "category": "linux_time"},
    "timer_gettime": {"lib": "libc", "purpose": "get POSIX timer current value", "category": "linux_time"},
    "timer_delete": {"lib": "libc", "purpose": "delete POSIX timer", "category": "linux_time"},
    "timer_getoverrun": {"lib": "libc", "purpose": "get POSIX timer overrun count", "category": "linux_time"},

    # --- Resource limits ---
    "getrlimit": {"lib": "libc", "purpose": "get resource usage limits", "category": "linux_process"},
    "setrlimit": {"lib": "libc", "purpose": "set resource usage limits", "category": "linux_process"},
    "prlimit64": {"lib": "libc", "purpose": "get/set resource limits (64-bit, per-process)", "category": "linux_process"},
    "getrusage": {"lib": "libc", "purpose": "get resource usage statistics", "category": "linux_process"},
    "sysinfo": {"lib": "libc", "purpose": "get system memory/load information", "category": "linux_process"},
    "uname": {"lib": "libc", "purpose": "get system identification info", "category": "linux_process"},

    # --- Misc modern syscalls ---
    "sendfile": {"lib": "libc", "purpose": "zero-copy data transfer between fds", "category": "linux_io"},
    "sendfile64": {"lib": "libc", "purpose": "zero-copy data transfer (64-bit offset)", "category": "linux_io"},
    "sync": {"lib": "libc", "purpose": "flush all filesystem caches to disk", "category": "linux_io"},
    "fsync": {"lib": "libc", "purpose": "flush file data and metadata to disk", "category": "linux_io"},
    "fdatasync": {"lib": "libc", "purpose": "flush file data to disk (no metadata)", "category": "linux_io"},
    "syncfs": {"lib": "libc", "purpose": "flush filesystem containing fd to disk", "category": "linux_io"},
    "fadvise64": {"lib": "libc", "purpose": "advise kernel about file access patterns", "category": "linux_io"},
    "posix_fadvise": {"lib": "libc", "purpose": "advise kernel on file access pattern", "category": "linux_io"},

    # --- Extended attributes ---
    "setxattr": {"lib": "libc", "purpose": "set extended file attribute", "category": "linux_fs"},
    "getxattr": {"lib": "libc", "purpose": "get extended file attribute", "category": "linux_fs"},
    "listxattr": {"lib": "libc", "purpose": "list extended file attributes", "category": "linux_fs"},
    "removexattr": {"lib": "libc", "purpose": "remove extended file attribute", "category": "linux_fs"},
    "fsetxattr": {"lib": "libc", "purpose": "set extended attribute by fd", "category": "linux_fs"},
    "fgetxattr": {"lib": "libc", "purpose": "get extended attribute by fd", "category": "linux_fs"},
    "flistxattr": {"lib": "libc", "purpose": "list extended attributes by fd", "category": "linux_fs"},
    "fremovexattr": {"lib": "libc", "purpose": "remove extended attribute by fd", "category": "linux_fs"},

    # --- Mount / filesystem ---
    "mount": {"lib": "libc", "purpose": "mount filesystem", "category": "linux_fs"},
    "umount2": {"lib": "libc", "purpose": "unmount filesystem with flags", "category": "linux_fs"},
    "pivot_root": {"lib": "libc", "purpose": "change root filesystem", "category": "linux_fs"},
    "statfs": {"lib": "libc", "purpose": "get filesystem statistics", "category": "linux_fs"},
    "fstatfs": {"lib": "libc", "purpose": "get filesystem statistics by fd", "category": "linux_fs"},

    # --- Futex (fast userspace mutex) ---
    "futex": {"lib": "libc", "purpose": "fast userspace locking primitive", "category": "linux_sync"},
    "futex_waitv": {"lib": "libc", "purpose": "wait on multiple futexes", "category": "linux_sync"},

    # --- ptrace / debugging ---
    "ptrace": {"lib": "libc", "purpose": "process trace (debugging/tracing)", "category": "linux_debug"},
    "process_vm_readv": {"lib": "libc", "purpose": "read from another process memory", "category": "linux_debug"},
    "process_vm_writev": {"lib": "libc", "purpose": "write to another process memory", "category": "linux_debug"},

    # --- cgroup / scheduling ---
    "sched_setaffinity": {"lib": "libc", "purpose": "set CPU affinity mask", "category": "linux_sched"},
    "sched_getaffinity": {"lib": "libc", "purpose": "get CPU affinity mask", "category": "linux_sched"},
    "sched_yield": {"lib": "libc", "purpose": "yield processor to other threads", "category": "linux_sched"},
    "sched_setscheduler": {"lib": "libc", "purpose": "set scheduling policy and priority", "category": "linux_sched"},
    "sched_getscheduler": {"lib": "libc", "purpose": "get scheduling policy", "category": "linux_sched"},
    "nice": {"lib": "libc", "purpose": "change process priority (nice value)", "category": "linux_sched"},
    "getpriority": {"lib": "libc", "purpose": "get scheduling priority", "category": "linux_sched"},
    "setpriority": {"lib": "libc", "purpose": "set scheduling priority", "category": "linux_sched"},

    # --- Misc ---
    "exit_group": {"lib": "libc", "purpose": "exit all threads in process", "category": "linux_process"},
    "_exit": {"lib": "libc", "purpose": "terminate process immediately", "category": "linux_process"},
    "set_tid_address": {"lib": "libc", "purpose": "set pointer to thread ID (for futex wake)", "category": "linux_process"},
    "arch_prctl": {"lib": "libc", "purpose": "set architecture-specific thread state", "category": "linux_process"},
    "set_thread_area": {"lib": "libc", "purpose": "set thread-local storage entry", "category": "linux_process"},
    "get_thread_area": {"lib": "libc", "purpose": "get thread-local storage entry", "category": "linux_process"},
    "personality": {"lib": "libc", "purpose": "set process execution domain", "category": "linux_process"},
    "capget": {"lib": "libc", "purpose": "get process capabilities", "category": "linux_security"},
    "capset": {"lib": "libc", "purpose": "set process capabilities", "category": "linux_security"},
}


# ---------------------------------------------------------------------------
# libc_ext_signatures (150 entry) — libc extension: dlmopen/dlinfo, stdio extra, string_ext (memmem/strnlen), search.h (tsearch), wide-char (wcs*), printf/scanf varyantlari.
# Kaynak: signature_db.py _LIBC_EXT_SIGNATURES.
# ---------------------------------------------------------------------------
_LIBC_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- Dynamic loading (extending _DYNLOAD_SIGNATURES) ---
    "dlopen": {"lib": "libdl", "purpose": "load shared library at runtime", "category": "dynload"},
    "dlsym": {"lib": "libdl", "purpose": "get symbol address from shared library", "category": "dynload"},
    "dlclose": {"lib": "libdl", "purpose": "unload shared library", "category": "dynload"},
    "dlerror": {"lib": "libdl", "purpose": "get last dynamic loading error string", "category": "dynload"},
    "dladdr": {"lib": "libdl", "purpose": "get info about address in loaded library", "category": "dynload"},
    "dlinfo": {"lib": "libdl", "purpose": "get information about shared library", "category": "dynload"},
    "dl_iterate_phdr": {"lib": "libdl", "purpose": "iterate over loaded ELF program headers", "category": "dynload"},

    # --- stdio (extending _STRING_STDLIB_SIGNATURES) ---
    "printf": {"lib": "libc", "purpose": "formatted output to stdout", "category": "string"},
    "fprintf": {"lib": "libc", "purpose": "formatted output to stream", "category": "string"},
    "sprintf": {"lib": "libc", "purpose": "formatted output to string buffer", "category": "string"},
    "snprintf": {"lib": "libc", "purpose": "formatted output with size limit", "category": "string"},
    "vprintf": {"lib": "libc", "purpose": "formatted output (va_list)", "category": "string"},
    "vfprintf": {"lib": "libc", "purpose": "formatted output to stream (va_list)", "category": "string"},
    "vsprintf": {"lib": "libc", "purpose": "formatted output to buffer (va_list)", "category": "string"},
    "vsnprintf": {"lib": "libc", "purpose": "formatted output with limit (va_list)", "category": "string"},
    "scanf": {"lib": "libc", "purpose": "formatted input from stdin", "category": "string"},
    "fscanf": {"lib": "libc", "purpose": "formatted input from stream", "category": "string"},
    "sscanf": {"lib": "libc", "purpose": "formatted input from string", "category": "string"},
    "puts": {"lib": "libc", "purpose": "write string to stdout with newline", "category": "string"},
    "fputs": {"lib": "libc", "purpose": "write string to stream", "category": "string"},
    "fgets": {"lib": "libc", "purpose": "read string from stream", "category": "string"},
    "getc": {"lib": "libc", "purpose": "read character from stream", "category": "string"},
    "fgetc": {"lib": "libc", "purpose": "read character from stream (function)", "category": "string"},
    "putc": {"lib": "libc", "purpose": "write character to stream", "category": "string"},
    "fputc": {"lib": "libc", "purpose": "write character to stream (function)", "category": "string"},
    "getchar": {"lib": "libc", "purpose": "read character from stdin", "category": "string"},
    "putchar": {"lib": "libc", "purpose": "write character to stdout", "category": "string"},
    "ungetc": {"lib": "libc", "purpose": "push character back to stream", "category": "string"},
    "perror": {"lib": "libc", "purpose": "print error message to stderr", "category": "string"},

    # --- String functions ---
    "strlen": {"lib": "libc", "purpose": "get string length", "category": "string"},
    "strnlen": {"lib": "libc", "purpose": "get string length with limit", "category": "string"},
    "strcmp": {"lib": "libc", "purpose": "compare two strings", "category": "string"},
    "strncmp": {"lib": "libc", "purpose": "compare strings with limit", "category": "string"},
    "strcasecmp": {"lib": "libc", "purpose": "case-insensitive string compare", "category": "string"},
    "strncasecmp": {"lib": "libc", "purpose": "case-insensitive compare with limit", "category": "string"},
    "strcpy": {"lib": "libc", "purpose": "copy string", "category": "string"},
    "strncpy": {"lib": "libc", "purpose": "copy string with limit", "category": "string"},
    "strlcpy": {"lib": "libc", "purpose": "copy string (safe, BSD)", "category": "string"},
    "strlcat": {"lib": "libc", "purpose": "concatenate string (safe, BSD)", "category": "string"},
    "strcat": {"lib": "libc", "purpose": "concatenate strings", "category": "string"},
    "strncat": {"lib": "libc", "purpose": "concatenate strings with limit", "category": "string"},
    "strstr": {"lib": "libc", "purpose": "find substring", "category": "string"},
    "strchr": {"lib": "libc", "purpose": "find first occurrence of character", "category": "string"},
    "strrchr": {"lib": "libc", "purpose": "find last occurrence of character", "category": "string"},
    "strpbrk": {"lib": "libc", "purpose": "find first of character set", "category": "string"},
    "strspn": {"lib": "libc", "purpose": "count chars from character set", "category": "string"},
    "strcspn": {"lib": "libc", "purpose": "count chars not in character set", "category": "string"},
    "strtok": {"lib": "libc", "purpose": "tokenize string (not thread-safe)", "category": "string"},
    "strtok_r": {"lib": "libc", "purpose": "tokenize string (reentrant)", "category": "string"},
    "strdup": {"lib": "libc", "purpose": "duplicate string (malloc + copy)", "category": "string"},
    "strndup": {"lib": "libc", "purpose": "duplicate string with limit", "category": "string"},
    "strerror": {"lib": "libc", "purpose": "get error message string", "category": "string"},
    "strerror_r": {"lib": "libc", "purpose": "get error message (reentrant)", "category": "string"},

    # --- Memory functions ---
    "malloc": {"lib": "libc", "purpose": "allocate heap memory", "category": "memory"},
    "free": {"lib": "libc", "purpose": "free heap memory", "category": "memory"},
    "calloc": {"lib": "libc", "purpose": "allocate and zero heap memory", "category": "memory"},
    "realloc": {"lib": "libc", "purpose": "resize heap memory block", "category": "memory"},
    "reallocarray": {"lib": "libc", "purpose": "resize with overflow check", "category": "memory"},
    "memcpy": {"lib": "libc", "purpose": "copy memory block", "category": "memory"},
    "memmove": {"lib": "libc", "purpose": "copy memory (overlap safe)", "category": "memory"},
    "memset": {"lib": "libc", "purpose": "fill memory with byte value", "category": "memory"},
    "memcmp": {"lib": "libc", "purpose": "compare memory blocks", "category": "memory"},
    "memchr": {"lib": "libc", "purpose": "find byte in memory", "category": "memory"},
    "memrchr": {"lib": "libc", "purpose": "find byte in memory (reverse)", "category": "memory"},
    "posix_memalign": {"lib": "libc", "purpose": "allocate aligned memory", "category": "memory"},
    "aligned_alloc": {"lib": "libc", "purpose": "allocate aligned memory (C11)", "category": "memory"},
    "memalign": {"lib": "libc", "purpose": "allocate aligned memory (deprecated)", "category": "memory"},
    "valloc": {"lib": "libc", "purpose": "allocate page-aligned memory (deprecated)", "category": "memory"},
    "pvalloc": {"lib": "libc", "purpose": "allocate pages (deprecated)", "category": "memory"},
    "malloc_usable_size": {"lib": "libc", "purpose": "get usable size of allocation", "category": "memory"},
    "explicit_bzero": {"lib": "libc", "purpose": "zero memory (not optimized out)", "category": "memory"},
    "bzero": {"lib": "libc", "purpose": "zero memory block (deprecated)", "category": "memory"},
    "bcopy": {"lib": "libc", "purpose": "copy memory (deprecated, use memcpy)", "category": "memory"},

    # --- pthread extended ---
    "pthread_create": {"lib": "libpthread", "purpose": "create new POSIX thread", "category": "thread"},
    "pthread_join": {"lib": "libpthread", "purpose": "wait for thread to terminate", "category": "thread"},
    "pthread_detach": {"lib": "libpthread", "purpose": "detach thread (auto cleanup on exit)", "category": "thread"},
    "pthread_exit": {"lib": "libpthread", "purpose": "terminate calling thread", "category": "thread"},
    "pthread_self": {"lib": "libpthread", "purpose": "get calling thread ID", "category": "thread"},
    "pthread_equal": {"lib": "libpthread", "purpose": "compare thread IDs", "category": "thread"},
    "pthread_cancel": {"lib": "libpthread", "purpose": "request thread cancellation", "category": "thread"},
    "pthread_mutex_init": {"lib": "libpthread", "purpose": "initialize mutex", "category": "thread"},
    "pthread_mutex_destroy": {"lib": "libpthread", "purpose": "destroy mutex", "category": "thread"},
    "pthread_mutex_lock": {"lib": "libpthread", "purpose": "lock mutex (blocking)", "category": "thread"},
    "pthread_mutex_trylock": {"lib": "libpthread", "purpose": "try to lock mutex (non-blocking)", "category": "thread"},
    "pthread_mutex_unlock": {"lib": "libpthread", "purpose": "unlock mutex", "category": "thread"},
    "pthread_mutex_timedlock": {"lib": "libpthread", "purpose": "lock mutex with timeout", "category": "thread"},
    "pthread_cond_init": {"lib": "libpthread", "purpose": "initialize condition variable", "category": "thread"},
    "pthread_cond_destroy": {"lib": "libpthread", "purpose": "destroy condition variable", "category": "thread"},
    "pthread_cond_wait": {"lib": "libpthread", "purpose": "wait on condition variable", "category": "thread"},
    "pthread_cond_timedwait": {"lib": "libpthread", "purpose": "wait on condition with timeout", "category": "thread"},
    "pthread_cond_signal": {"lib": "libpthread", "purpose": "signal one waiting thread", "category": "thread"},
    "pthread_cond_broadcast": {"lib": "libpthread", "purpose": "signal all waiting threads", "category": "thread"},
    "pthread_rwlock_init": {"lib": "libpthread", "purpose": "initialize read-write lock", "category": "thread"},
    "pthread_rwlock_destroy": {"lib": "libpthread", "purpose": "destroy read-write lock", "category": "thread"},
    "pthread_rwlock_rdlock": {"lib": "libpthread", "purpose": "acquire read lock", "category": "thread"},
    "pthread_rwlock_wrlock": {"lib": "libpthread", "purpose": "acquire write lock", "category": "thread"},
    "pthread_rwlock_unlock": {"lib": "libpthread", "purpose": "release read-write lock", "category": "thread"},
    "pthread_rwlock_tryrdlock": {"lib": "libpthread", "purpose": "try acquire read lock", "category": "thread"},
    "pthread_rwlock_trywrlock": {"lib": "libpthread", "purpose": "try acquire write lock", "category": "thread"},
    "pthread_spin_init": {"lib": "libpthread", "purpose": "initialize spinlock", "category": "thread"},
    "pthread_spin_destroy": {"lib": "libpthread", "purpose": "destroy spinlock", "category": "thread"},
    "pthread_spin_lock": {"lib": "libpthread", "purpose": "acquire spinlock", "category": "thread"},
    "pthread_spin_trylock": {"lib": "libpthread", "purpose": "try acquire spinlock", "category": "thread"},
    "pthread_spin_unlock": {"lib": "libpthread", "purpose": "release spinlock", "category": "thread"},
    "pthread_key_create": {"lib": "libpthread", "purpose": "create thread-specific data key", "category": "thread"},
    "pthread_key_delete": {"lib": "libpthread", "purpose": "delete thread-specific data key", "category": "thread"},
    "pthread_getspecific": {"lib": "libpthread", "purpose": "get thread-specific data value", "category": "thread"},
    "pthread_setspecific": {"lib": "libpthread", "purpose": "set thread-specific data value", "category": "thread"},
    "pthread_once": {"lib": "libpthread", "purpose": "one-time initialization", "category": "thread"},
    "pthread_barrier_init": {"lib": "libpthread", "purpose": "initialize barrier", "category": "thread"},
    "pthread_barrier_destroy": {"lib": "libpthread", "purpose": "destroy barrier", "category": "thread"},
    "pthread_barrier_wait": {"lib": "libpthread", "purpose": "wait at barrier", "category": "thread"},
    "pthread_attr_init": {"lib": "libpthread", "purpose": "initialize thread attributes", "category": "thread"},
    "pthread_attr_destroy": {"lib": "libpthread", "purpose": "destroy thread attributes", "category": "thread"},
    "pthread_attr_setdetachstate": {"lib": "libpthread", "purpose": "set thread detach state attribute", "category": "thread"},
    "pthread_attr_setstacksize": {"lib": "libpthread", "purpose": "set thread stack size attribute", "category": "thread"},

    # --- Semaphores (sem_*) ---
    "sem_init": {"lib": "libpthread", "purpose": "initialize unnamed semaphore", "category": "thread"},
    "sem_destroy": {"lib": "libpthread", "purpose": "destroy unnamed semaphore", "category": "thread"},
    "sem_wait": {"lib": "libpthread", "purpose": "decrement (lock) semaphore", "category": "thread"},
    "sem_trywait": {"lib": "libpthread", "purpose": "try decrement semaphore (non-blocking)", "category": "thread"},
    "sem_timedwait": {"lib": "libpthread", "purpose": "decrement semaphore with timeout", "category": "thread"},
    "sem_post": {"lib": "libpthread", "purpose": "increment (unlock) semaphore", "category": "thread"},
    "sem_getvalue": {"lib": "libpthread", "purpose": "get current semaphore value", "category": "thread"},
    "sem_open": {"lib": "libpthread", "purpose": "open named semaphore", "category": "thread"},
    "sem_close": {"lib": "libpthread", "purpose": "close named semaphore", "category": "thread"},
    "sem_unlink": {"lib": "libpthread", "purpose": "remove named semaphore", "category": "thread"},

    # --- Conversion / stdlib ---
    "atoi": {"lib": "libc", "purpose": "convert string to integer", "category": "string"},
    "atol": {"lib": "libc", "purpose": "convert string to long integer", "category": "string"},
    "atof": {"lib": "libc", "purpose": "convert string to double", "category": "string"},
    "strtol": {"lib": "libc", "purpose": "convert string to long with base", "category": "string"},
    "strtoul": {"lib": "libc", "purpose": "convert string to unsigned long", "category": "string"},
    "strtoll": {"lib": "libc", "purpose": "convert string to long long", "category": "string"},
    "strtoull": {"lib": "libc", "purpose": "convert string to unsigned long long", "category": "string"},
    "strtod": {"lib": "libc", "purpose": "convert string to double", "category": "string"},
    "strtof": {"lib": "libc", "purpose": "convert string to float", "category": "string"},

    # --- stdlib ---
    "abort": {"lib": "libc", "purpose": "abort process (raise SIGABRT)", "category": "process"},
    "exit": {"lib": "libc", "purpose": "normal process termination", "category": "process"},
    "atexit": {"lib": "libc", "purpose": "register function called at exit", "category": "process"},
    "system": {"lib": "libc", "purpose": "execute shell command", "category": "process"},
    "getenv": {"lib": "libc", "purpose": "get environment variable value", "category": "process"},
    "setenv": {"lib": "libc", "purpose": "set environment variable", "category": "process"},
    "unsetenv": {"lib": "libc", "purpose": "remove environment variable", "category": "process"},
    "qsort": {"lib": "libc", "purpose": "sort array (quicksort)", "category": "stdlib"},
    "bsearch": {"lib": "libc", "purpose": "binary search sorted array", "category": "stdlib"},
    "abs": {"lib": "libc", "purpose": "absolute value of integer", "category": "stdlib"},
    "labs": {"lib": "libc", "purpose": "absolute value of long", "category": "stdlib"},
    "div": {"lib": "libc", "purpose": "integer division with remainder", "category": "stdlib"},
    "rand": {"lib": "libc", "purpose": "generate pseudo-random number", "category": "stdlib"},
    "srand": {"lib": "libc", "purpose": "seed pseudo-random generator", "category": "stdlib"},
    "rand_r": {"lib": "libc", "purpose": "generate pseudo-random (reentrant)", "category": "stdlib"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category("linux_system") bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur.
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "linux_syscall_signatures": _LINUX_SYSCALL_SIGNATURES_DATA,
    "linux_syscall_ext_signatures": _LINUX_SYSCALL_EXT_SIGNATURES_DATA,
    "libc_ext_signatures": _LIBC_EXT_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
