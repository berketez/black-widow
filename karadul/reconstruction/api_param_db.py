"""API Parametre Veritabani — bilinen fonksiyonlarin parametre isimlerini tutar.

Kullanim:
    db = APIParamDB()
    names = db.get_param_names("send")
    # -> ["sockfd", "buf", "len", "flags"]

    # Ghidra decompile ciktisinda:
    #   send(param_1, param_2, param_3, 0)
    # olursa:
    #   param_1 -> sockfd
    #   param_2 -> buf
    #   param_3 -> len
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------
# POSIX / libc
# ---------------------------------------------------------------
_POSIX_PARAMS: dict[str, list[str]] = {
    # File I/O
    "open": ["pathname", "flags", "mode"],
    "close": ["fd"],
    "read": ["fd", "buf", "count"],
    "write": ["fd", "buf", "count"],
    "lseek": ["fd", "offset", "whence"],
    "pread": ["fd", "buf", "count", "offset"],
    "pwrite": ["fd", "buf", "count", "offset"],
    "fopen": ["pathname", "mode"],
    "fclose": ["stream"],
    "fread": ["ptr", "size", "nmemb", "stream"],
    "fwrite": ["ptr", "size", "nmemb", "stream"],
    "fgets": ["str", "size", "stream"],
    "fputs": ["str", "stream"],
    "fseek": ["stream", "offset", "whence"],
    "ftell": ["stream"],
    "fflush": ["stream"],
    "stat": ["pathname", "statbuf"],
    "fstat": ["fd", "statbuf"],
    "lstat": ["pathname", "statbuf"],
    "access": ["pathname", "mode"],
    "chmod": ["pathname", "mode"],
    "chown": ["pathname", "owner", "group"],
    "mkdir": ["pathname", "mode"],
    "rmdir": ["pathname"],
    "unlink": ["pathname"],
    "rename": ["oldpath", "newpath"],
    "opendir": ["name"],
    "readdir": ["dirp"],
    "closedir": ["dirp"],
    "dup": ["oldfd"],
    "dup2": ["oldfd", "newfd"],
    "pipe": ["pipefd"],
    "fcntl": ["fd", "cmd"],
    "ioctl": ["fd", "request"],
    "truncate": ["path", "length"],
    "ftruncate": ["fd", "length"],
    "symlink": ["target", "linkpath"],
    "readlink": ["pathname", "buf", "bufsiz"],
    "realpath": ["path", "resolved_path"],

    # Memory
    "malloc": ["size"],
    "calloc": ["nmemb", "size"],
    "realloc": ["ptr", "size"],
    "free": ["ptr"],
    "mmap": ["addr", "length", "prot", "flags", "fd", "offset"],
    "munmap": ["addr", "length"],
    "mprotect": ["addr", "len", "prot"],
    "memcpy": ["dest", "src", "n"],
    "memmove": ["dest", "src", "n"],
    "memset": ["s", "c", "n"],
    "memcmp": ["s1", "s2", "n"],
    "memchr": ["s", "c", "n"],

    # String
    "strlen": ["s"],
    "strcmp": ["s1", "s2"],
    "strncmp": ["s1", "s2", "n"],
    "strcpy": ["dest", "src"],
    "strncpy": ["dest", "src", "n"],
    "strcat": ["dest", "src"],
    "strncat": ["dest", "src", "n"],
    "strstr": ["haystack", "needle"],
    "strchr": ["s", "c"],
    "strrchr": ["s", "c"],
    "strdup": ["s"],
    "strtok": ["str", "delim"],
    "strtok_r": ["str", "delim", "saveptr"],

    # Formatting
    "printf": ["format"],
    "fprintf": ["stream", "format"],
    "sprintf": ["str", "format"],
    "snprintf": ["str", "size", "format"],
    "sscanf": ["str", "format"],

    # Conversion
    "atoi": ["nptr"],
    "atol": ["nptr"],
    "atof": ["nptr"],
    "strtol": ["nptr", "endptr", "base"],
    "strtoul": ["nptr", "endptr", "base"],
    "strtod": ["nptr", "endptr"],

    # Network
    "socket": ["domain", "type", "protocol"],
    "bind": ["sockfd", "addr", "addrlen"],
    "listen": ["sockfd", "backlog"],
    "accept": ["sockfd", "addr", "addrlen"],
    "connect": ["sockfd", "addr", "addrlen"],
    "send": ["sockfd", "buf", "len", "flags"],
    "recv": ["sockfd", "buf", "len", "flags"],
    "sendto": ["sockfd", "buf", "len", "flags", "dest_addr", "addrlen"],
    "recvfrom": ["sockfd", "buf", "len", "flags", "src_addr", "addrlen"],
    "setsockopt": ["sockfd", "level", "optname", "optval", "optlen"],
    "getsockopt": ["sockfd", "level", "optname", "optval", "optlen"],
    "shutdown": ["sockfd", "how"],
    "select": ["nfds", "readfds", "writefds", "exceptfds", "timeout"],
    "poll": ["fds", "nfds", "timeout"],
    "getaddrinfo": ["node", "service", "hints", "res"],
    "freeaddrinfo": ["res"],
    "inet_pton": ["af", "src", "dst"],
    "inet_ntop": ["af", "src", "dst", "size"],
    "htons": ["hostshort"],
    "ntohs": ["netshort"],
    "htonl": ["hostlong"],

    # Process
    "fork": [],
    "execve": ["pathname", "argv", "envp"],
    "execvp": ["file", "argv"],
    "waitpid": ["pid", "wstatus", "options"],
    "kill": ["pid", "sig"],
    "signal": ["signum", "handler"],
    "sigaction": ["signum", "act", "oldact"],
    "getpid": [],
    "getppid": [],
    "exit": ["status"],
    "_exit": ["status"],
    "system": ["command"],
    "popen": ["command", "type"],
    "pclose": ["stream"],

    # Thread
    "pthread_create": ["thread", "attr", "start_routine", "arg"],
    "pthread_join": ["thread", "retval"],
    "pthread_mutex_init": ["mutex", "attr"],
    "pthread_mutex_lock": ["mutex"],
    "pthread_mutex_unlock": ["mutex"],
    "pthread_mutex_destroy": ["mutex"],
    "pthread_cond_init": ["cond", "attr"],
    "pthread_cond_wait": ["cond", "mutex"],
    "pthread_cond_signal": ["cond"],
    "pthread_cond_broadcast": ["cond"],

    # Dynamic loading
    "dlopen": ["filename", "flags"],
    "dlsym": ["handle", "symbol"],
    "dlclose": ["handle"],

    # Time
    "time": ["tloc"],
    "gettimeofday": ["tv", "tz"],
    "sleep": ["seconds"],
    "usleep": ["usec"],
    "nanosleep": ["req", "rem"],

    # Error
    "strerror": ["errnum"],
    "perror": ["s"],

    # Misc
    "qsort": ["base", "nmemb", "size", "compar"],
    "bsearch": ["key", "base", "nmemb", "size", "compar"],
    "getenv": ["name"],
    "setenv": ["name", "value", "overwrite"],
    "atexit": ["func"],
}

# ---------------------------------------------------------------
# OpenSSL
# ---------------------------------------------------------------
_OPENSSL_PARAMS: dict[str, list[str]] = {
    "SSL_CTX_new": ["method"],
    "SSL_new": ["ctx"],
    "SSL_set_fd": ["ssl", "fd"],
    "SSL_connect": ["ssl"],
    "SSL_accept": ["ssl"],
    "SSL_read": ["ssl", "buf", "num"],
    "SSL_write": ["ssl", "buf", "num"],
    "SSL_shutdown": ["ssl"],
    "SSL_free": ["ssl"],
    "SSL_CTX_free": ["ctx"],
    "SSL_get_error": ["ssl", "ret"],
    "SSL_CTX_set_verify": ["ctx", "mode", "callback"],
    "SSL_CTX_use_certificate_file": ["ctx", "file", "type"],
    "SSL_CTX_use_PrivateKey_file": ["ctx", "file", "type"],
    "SSL_CTX_load_verify_locations": ["ctx", "CAfile", "CApath"],
    "EVP_EncryptInit_ex": ["ctx", "type", "impl", "key", "iv"],
    "EVP_EncryptUpdate": ["ctx", "out", "outl", "in", "inl"],
    "EVP_EncryptFinal_ex": ["ctx", "out", "outl"],
    "EVP_DecryptInit_ex": ["ctx", "type", "impl", "key", "iv"],
    "EVP_DecryptUpdate": ["ctx", "out", "outl", "in", "inl"],
    "EVP_DecryptFinal_ex": ["ctx", "out", "outl"],
    "EVP_DigestInit_ex": ["ctx", "type", "impl"],
    "EVP_DigestUpdate": ["ctx", "data", "count"],
    "EVP_DigestFinal_ex": ["ctx", "md", "size"],
    "EVP_CIPHER_CTX_new": [],
    "EVP_CIPHER_CTX_free": ["ctx"],
    "EVP_MD_CTX_new": [],
    "EVP_MD_CTX_free": ["ctx"],
    "RAND_bytes": ["buf", "num"],
    "BIO_new": ["type"],
    "BIO_free": ["bio"],
    "BIO_read": ["bio", "buf", "len"],
    "BIO_write": ["bio", "buf", "len"],
}

# ---------------------------------------------------------------
# macOS / Apple
# ---------------------------------------------------------------
_APPLE_PARAMS: dict[str, list[str]] = {
    "dispatch_async": ["queue", "block"],
    "dispatch_sync": ["queue", "block"],
    "dispatch_queue_create": ["label", "attr"],
    "dispatch_get_main_queue": [],
    "dispatch_get_global_queue": ["identifier", "flags"],
    "dispatch_once": ["predicate", "block"],
    "dispatch_semaphore_create": ["value"],
    "dispatch_semaphore_wait": ["dsema", "timeout"],
    "dispatch_semaphore_signal": ["dsema"],
    "dispatch_group_create": [],
    "dispatch_group_enter": ["group"],
    "dispatch_group_leave": ["group"],
    "objc_msgSend": ["self", "selector"],
    "objc_getClass": ["name"],
    "CFStringCreateWithCString": ["alloc", "cStr", "encoding"],
    "CFRelease": ["cf"],
    "CFRetain": ["cf"],
    "SecItemAdd": ["attributes", "result"],
    "SecItemCopyMatching": ["query", "result"],
}

# ---------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------
_SQLITE_PARAMS: dict[str, list[str]] = {
    "sqlite3_open": ["filename", "ppDb"],
    "sqlite3_open_v2": ["filename", "ppDb", "flags", "zVfs"],
    "sqlite3_close": ["db"],
    "sqlite3_exec": ["db", "sql", "callback", "arg", "errmsg"],
    "sqlite3_prepare_v2": ["db", "zSql", "nByte", "ppStmt", "pzTail"],
    "sqlite3_step": ["pStmt"],
    "sqlite3_finalize": ["pStmt"],
    "sqlite3_bind_int": ["pStmt", "index", "value"],
    "sqlite3_bind_text": ["pStmt", "index", "value", "n", "destructor"],
    "sqlite3_bind_blob": ["pStmt", "index", "value", "n", "destructor"],
    "sqlite3_column_int": ["pStmt", "iCol"],
    "sqlite3_column_text": ["pStmt", "iCol"],
    "sqlite3_column_blob": ["pStmt", "iCol"],
    "sqlite3_column_bytes": ["pStmt", "iCol"],
    "sqlite3_errmsg": ["db"],
}

# ---------------------------------------------------------------
# zlib
# ---------------------------------------------------------------
_ZLIB_PARAMS: dict[str, list[str]] = {
    "deflateInit": ["strm", "level"],
    "deflate": ["strm", "flush"],
    "deflateEnd": ["strm"],
    "inflateInit": ["strm"],
    "inflate": ["strm", "flush"],
    "inflateEnd": ["strm"],
    "compress": ["dest", "destLen", "source", "sourceLen"],
    "uncompress": ["dest", "destLen", "source", "sourceLen"],
    "crc32": ["crc", "buf", "len"],
}

# ---------------------------------------------------------------
# libcurl
# ---------------------------------------------------------------
_CURL_PARAMS: dict[str, list[str]] = {
    "curl_easy_init": [],
    "curl_easy_setopt": ["curl", "option", "parameter"],
    "curl_easy_perform": ["curl"],
    "curl_easy_cleanup": ["curl"],
    "curl_easy_getinfo": ["curl", "info", "arg"],
    "curl_global_init": ["flags"],
    "curl_slist_append": ["list", "string"],
    "curl_slist_free_all": ["list"],
}



# ---------------------------------------------------------------
# Callback parametre veritabani -- hangi API'nin hangi parametresi
# fonksiyon pointer (callback) bekliyor.
# Format: {api_name: {param_index: suggested_callback_name}}
# ---------------------------------------------------------------
_CALLBACK_PARAMS: dict[str, dict[int, str]] = {
    # SSL
    "SSL_CTX_set_verify": {2: "verify_callback"},
    "SSL_CTX_set_cert_verify_callback": {1: "cert_verify_callback"},
    "SSL_CTX_set_info_callback": {1: "info_callback"},
    "SSL_set_verify": {2: "verify_callback"},
    # POSIX / libc
    "qsort": {3: "compare_func"},
    "bsearch": {4: "compare_func"},
    "signal": {1: "signal_handler"},
    "sigaction": {1: "signal_handler"},
    "pthread_create": {2: "thread_start_routine"},
    "atexit": {0: "exit_handler"},
    # Apple/GCD
    "dispatch_async": {1: "dispatch_block"},
    "dispatch_sync": {1: "dispatch_block"},
    "dispatch_once": {1: "once_block"},
    "dispatch_apply": {2: "apply_block"},
    # SQLite
    "sqlite3_exec": {2: "exec_callback"},
    "sqlite3_create_function": {4: "xFunc"},
    "sqlite3_create_function_v2": {4: "xFunc"},
    "sqlite3_set_authorizer": {1: "auth_callback"},
    "sqlite3_busy_handler": {1: "busy_handler"},
    "sqlite3_commit_hook": {1: "commit_hook"},
    "sqlite3_rollback_hook": {1: "rollback_hook"},
    "sqlite3_update_hook": {1: "update_hook"},
    # libcurl
    "curl_easy_setopt": {2: "write_callback"},
    # libevent / kqueue
    "event_new": {3: "event_callback"},
    "event_set": {3: "event_callback"},
    # CoreFoundation
    "CFRunLoopTimerCreate": {5: "timer_callback"},
    "CFRunLoopObserverCreate": {4: "observer_callback"},
    # Other
    "dlsym": {1: "symbol_func"},  # dlsym 2. param isim ama pointer donuyor
}

# Mach-O underscore prefix versiyonlari
_CALLBACK_PARAMS_PREFIXED: dict[str, dict[int, str]] = {
    f"_{k}": v for k, v in _CALLBACK_PARAMS.items()
}
_CALLBACK_PARAMS.update(_CALLBACK_PARAMS_PREFIXED)


class APIParamDB:
    """Bilinen API fonksiyonlarinin parametre isimlerini tutar."""

    def __init__(self) -> None:
        self._db: dict[str, list[str]] = {}
        self._callback_db: dict[str, dict[int, str]] = dict(_CALLBACK_PARAMS)
        self._load_builtins()

    def _load_builtins(self) -> None:
        for source in [_POSIX_PARAMS, _OPENSSL_PARAMS, _APPLE_PARAMS,
                       _SQLITE_PARAMS, _ZLIB_PARAMS, _CURL_PARAMS]:
            self._db.update(source)
        # Mach-O underscore prefix versiyonlari
        prefixed = {}
        for name, params in self._db.items():
            prefixed[f"_{name}"] = params
        self._db.update(prefixed)

        # Fortran runtime + BLAS/LAPACK parametre isimleri
        try:
            from karadul.reconstruction.fortran_param_db import _ALL_FORTRAN_PARAMS
            self._db.update(_ALL_FORTRAN_PARAMS)
        except ImportError:
            logger.debug("fortran_param_db import edilemedi, Fortran parametreleri atlanıyor")

        logger.info("APIParamDB: %d fonksiyon, parametre isimleri yuklendi", len(self._db))

    def get_param_names(self, func_name: str) -> list[str] | None:
        """Fonksiyonun parametre isimlerini dondur."""
        return self._db.get(func_name)

    def propagate_params(self, c_code: str) -> dict[str, str]:
        """C kodundaki API cagrilarindan parametre isimlerini propagate et.

        Returns:
            {param_N: suggested_name} dict'i
        """
        renames: dict[str, str] = {}
        # func_name(arg1, arg2, ...) pattern'i bul
        call_re = re.compile(
            r'\b(' + '|'.join(re.escape(n) for n in sorted(self._db, key=len, reverse=True))
            + r')\s*\(([^)]*)\)'
        )

        for match in call_re.finditer(c_code):
            func_name = match.group(1)
            args_str = match.group(2)
            param_names = self._db.get(func_name)
            if not param_names:
                continue

            # Argumanlari parse et (basit virgul split)
            args = [a.strip() for a in args_str.split(",")]

            for i, (arg, pname) in enumerate(zip(args, param_names)):
                # Sadece param_N veya local_XX gibi generic isimleri rename et
                if re.match(r'^(param_\d+|local_[0-9a-fA-F]+|[a-z]Var\d+)$', arg):
                    if arg not in renames:
                        renames[arg] = pname

        return renames

    @staticmethod
    def _extract_balanced_args(c_code: str, start: int) -> str | None:
        """Parantez dengeli arguman listesini cikar.

        c_code[start] bir '(' olmali. Dengelenmis ')' bulunana kadar tara.

        Args:
            c_code: C kaynak kodu.
            start: Acilan parantezin pozisyonu.

        Returns:
            Parantez icindeki arguman string'i (parantezler haric) veya None.
        """
        if start >= len(c_code) or c_code[start] != '(':
            return None
        depth = 0
        i = start
        while i < len(c_code):
            ch = c_code[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    return c_code[start + 1:i]
            i += 1
        return None

    @staticmethod
    def _split_args_balanced(args_str: str) -> list[str]:
        """Arguman string'ini parantez-dengelemeli virgullerden ayir.

        Nested parantez, koseli parantez ve suslu parantez icindeki
        virgulleri saymiyor.

        Args:
            args_str: Parantez icindeki arguman string'i.

        Returns:
            Arguman listesi.
        """
        args: list[str] = []
        depth = 0
        current: list[str] = []
        for ch in args_str:
            if ch in '([{':
                depth += 1
                current.append(ch)
            elif ch in ')]}':
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(current).strip())
                current = []
            else:
                current.append(ch)
        # Son arguman
        rest = ''.join(current).strip()
        if rest:
            args.append(rest)
        return args

    def reverse_propagate_function_names(self, c_code: str) -> dict[str, str]:
        """Bilinen API cagrilarinda FUN_xxx parametre olarak geciyorsa isim ver.

        Ornek:
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, FUN_1000abc);
            -> FUN_1000abc = "verify_callback"

            qsort(arr, n, sizeof(int), FUN_deadbeef);
            -> FUN_deadbeef = "compare_func"

            pthread_create(&thread, NULL, FUN_cafebabe, arg);
            -> FUN_cafebabe = "thread_start_routine"

        Strateji:
        1. Callback DB: API'nin belirli parametresi callback bekliyorsa
           (orn. qsort 4. param = compare fonksiyonu), FUN_xxx'e dogrudan isim ver.
        2. Generic param propagation: API'nin parametre isminden isim cikar
           (orn. signal(signum, FUN_xxx) -> FUN_xxx = "signal_handler")

        Returns:
            {FUN_xxx: suggested_name} dict'i
        """
        renames: dict[str, str] = {}

        # FUN_xxx pattern -- Ghidra auto-generated function names
        fun_re = re.compile(r'^FUN_[0-9a-fA-F]+$')

        # Tum bilinen API cagrilarini bul -- sadece fonksiyon adini ve
        # acilan parantezin pozisyonunu yakala, argumanlari balanced parse et
        # Hem _db hem _callback_db fonksiyonlarini kapsayacak birlesik kumeyi kullan
        all_known = set(self._db.keys()) | set(self._callback_db.keys())
        if not all_known:
            return renames

        # func_name( pattern'ini bul, argindan balanced parse yap
        call_start_re = re.compile(
            r'\b(' + '|'.join(re.escape(n) for n in sorted(all_known, key=len, reverse=True))
            + r')\s*\('
        )

        for match in call_start_re.finditer(c_code):
            func_name = match.group(1)
            # Acilan parantezin pozisyonu: match.end() - 1 (son karakter '(')
            paren_pos = match.end() - 1
            args_str = self._extract_balanced_args(c_code, paren_pos)
            if args_str is None:
                continue

            # Argumanlari balanced parse et (nested parantezleri dogru isle)
            args = self._split_args_balanced(args_str)

            for i, arg in enumerate(args):
                # Sadece FUN_xxx pattern'ine uyan argumanlari isle
                if not fun_re.match(arg):
                    continue

                # Zaten isimlendirilmis mi
                if arg in renames:
                    continue

                # 1. Callback DB'den bak
                callback_info = self._callback_db.get(func_name)
                if callback_info and i in callback_info:
                    renames[arg] = callback_info[i]
                    continue

                # 2. Parametre ismi "callback", "handler", "func", "routine" iceriyorsa
                param_names = self._db.get(func_name)
                if param_names and i < len(param_names):
                    pname = param_names[i].lower()
                    callback_hints = ("callback", "handler", "func", "routine",
                                      "hook", "block", "compar")
                    if any(hint in pname for hint in callback_hints):
                        renames[arg] = param_names[i]

        return renames

    def __len__(self) -> int:
        return len(self._db)
