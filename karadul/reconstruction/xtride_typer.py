"""XTRIDE-inspired N-gram tipi cikarimi -- decompiled C kodundan degisken tiplerini tahmin et.

XTRIDE (Seidel et al., 2026) n-gram tabanli tip inference yaklasimini Python'da
implement eder. Orijinal Rust CLI yerine, decompiled C kodundan token dizilerini
cikarip bilinen pattern veritabanina gore degisken tiplerini tahmin eder.

Uygulama kategorileri:
    1. API Parametre Tipleri -- bilinen fonksiyonlarin parametre pozisyonlarindan tip cikar
    2. Operator Kaliplari -- ++, *, ->, [], &, | gibi operatorlerden tip tahmin et
    3. Dongu Kaliplari -- for/while pattern'lerinden dongu degisken tiplerini cikar
    4. Karsilastirma -- NULL, '\\0', literal karsilastirmalarindan tip cikar
    5. Atama -- malloc, fopen, socket gibi donuslerin tipini tahmin et
    6. Bildirim -- Ghidra ciktisindaki undefined/long/int bildirimi iyilestirmeleri

Kullanim:
    from karadul.reconstruction.xtride_typer import XTrideTyper

    typer = XTrideTyper()
    results = typer.infer_types(func_code, "my_function")
    # -> {"param_1": ("int", 0.85, "api_param"), "local_10": ("char *", 0.65, "operator")}

Performans hedefi: <1ms / fonksiyon.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bayesian confidence merging
# ---------------------------------------------------------------------------

def _bayesian_merge_confidences(confidences: list[float]) -> float:
    """Bayesian log-odds fusion -- birden fazla kanit kaynagini birlestirir.

    Uniform prior (0.5) ile baslar, her confidence degerini log-odds olarak
    ekler ve sigmoid ile tekrar olasiliga donusturur. Bu yontem additive
    formule gore matematiksel olarak dogru ve [0,1] araligi korur.

    Args:
        confidences: Her kanit kaynagindan gelen confidence degerleri.

    Returns:
        float: Birlesmis posterior confidence [0.01, 0.99].
    """
    if not confidences:
        return 0.0
    # Uniform prior (0.5) -> log_odds baslangic = 0
    log_odds = 0.0
    for conf in confidences:
        conf = max(0.01, min(0.99, conf))  # clamp to avoid log(0)
        log_odds += math.log(conf / (1.0 - conf))
    # Sigmoid
    posterior = 1.0 / (1.0 + math.exp(-log_odds))
    return max(0.01, min(0.99, posterior))


# ---------------------------------------------------------------------------
# Sonuc veri yapisi
# ---------------------------------------------------------------------------


@dataclass
class TypeInference:
    """Tek bir degisken icin tip tahmini.

    Attributes:
        var_name: Degisken adi (orn: param_1, local_10).
        inferred_type: Tahmin edilen C tipi (orn: int, char *, FILE *).
        confidence: Guven skoru [0.0, 1.0].
        source: Tahmin kaynagi (api_param, operator, loop, comparison, assignment, declaration).
        evidence: Kanit aciklamasi.
    """

    var_name: str
    inferred_type: str
    confidence: float
    source: str
    evidence: str = ""


@dataclass
class XTrideResult:
    """Fonksiyon bazli XTRIDE tip cikarimi sonucu.

    Attributes:
        func_name: Fonksiyon adi.
        inferences: Degisken -> TypeInference eslesmesi.
        total_inferred: Toplam tahmin edilen degisken sayisi.
    """

    func_name: str
    inferences: dict[str, TypeInference] = field(default_factory=dict)
    total_inferred: int = 0


# ---------------------------------------------------------------------------
# Confidence sabitleri
# ---------------------------------------------------------------------------
CONFIDENCE_API_PARAM = 0.85       # API parametre pozisyonundan
CONFIDENCE_RETURN_TYPE = 0.85     # Bilinen fonksiyon donus tipi
CONFIDENCE_OPERATOR = 0.65        # Operator pattern'inden
CONFIDENCE_LOOP = 0.70            # Dongu pattern'inden
CONFIDENCE_COMPARISON = 0.60      # Karsilastirma pattern'inden
CONFIDENCE_ASSIGNMENT = 0.80      # Atama/donus degeri pattern'inden
CONFIDENCE_DECLARATION = 0.50     # Ghidra bildiriminden iyilestirme
CONFIDENCE_CAST = 0.80            # Explicit cast'ten
CONFIDENCE_SIZEOF = 0.70          # sizeof() kullanim pattern'inden
CONFIDENCE_BITWISE = 0.60         # Bitwise operator pattern'inden
CONFIDENCE_STRING_LITERAL = 0.85  # String literal atamasi

# ---------------------------------------------------------------------------
# API Parametre Tip Veritabani
# ---------------------------------------------------------------------------
# Format: {func_name: [(param_idx, param_type), ...]}
# Sadece parametre tip bilgisini tutar (isimler api_param_db'de).

_API_PARAM_TYPES: dict[str, list[tuple[int, str]]] = {
    # --- Memory ---
    "malloc": [(0, "size_t")],
    "calloc": [(0, "size_t"), (1, "size_t")],
    "realloc": [(0, "void *"), (1, "size_t")],
    "free": [(0, "void *")],
    "memcpy": [(0, "void *"), (1, "const void *"), (2, "size_t")],
    "memmove": [(0, "void *"), (1, "const void *"), (2, "size_t")],
    "memset": [(0, "void *"), (1, "int"), (2, "size_t")],
    "memcmp": [(0, "const void *"), (1, "const void *"), (2, "size_t")],
    "memchr": [(0, "const void *"), (1, "int"), (2, "size_t")],
    "mmap": [(0, "void *"), (1, "size_t"), (2, "int"), (3, "int"), (4, "int"), (5, "off_t")],
    "munmap": [(0, "void *"), (1, "size_t")],
    "mprotect": [(0, "void *"), (1, "size_t"), (2, "int")],
    "brk": [(0, "void *")],
    "sbrk": [(0, "intptr_t")],
    # --- String ---
    "strlen": [(0, "const char *")],
    "strcmp": [(0, "const char *"), (1, "const char *")],
    "strncmp": [(0, "const char *"), (1, "const char *"), (2, "size_t")],
    "strcpy": [(0, "char *"), (1, "const char *")],
    "strncpy": [(0, "char *"), (1, "const char *"), (2, "size_t")],
    "strcat": [(0, "char *"), (1, "const char *")],
    "strncat": [(0, "char *"), (1, "const char *"), (2, "size_t")],
    "strstr": [(0, "const char *"), (1, "const char *")],
    "strchr": [(0, "const char *"), (1, "int")],
    "strrchr": [(0, "const char *"), (1, "int")],
    "strdup": [(0, "const char *")],
    "strtok": [(0, "char *"), (1, "const char *")],
    "strtok_r": [(0, "char *"), (1, "const char *"), (2, "char **")],
    "stpcpy": [(0, "char *"), (1, "const char *")],
    "stpncpy": [(0, "char *"), (1, "const char *"), (2, "size_t")],
    "strsep": [(0, "char **"), (1, "const char *")],
    "strspn": [(0, "const char *"), (1, "const char *")],
    "strcspn": [(0, "const char *"), (1, "const char *")],
    "strpbrk": [(0, "const char *"), (1, "const char *")],
    # --- wchar ---
    "wcslen": [(0, "const wchar_t *")],
    "wcscpy": [(0, "wchar_t *"), (1, "const wchar_t *")],
    "wcsncpy": [(0, "wchar_t *"), (1, "const wchar_t *"), (2, "size_t")],
    "wcscat": [(0, "wchar_t *"), (1, "const wchar_t *")],
    "wcscmp": [(0, "const wchar_t *"), (1, "const wchar_t *")],
    "wmemcpy": [(0, "wchar_t *"), (1, "const wchar_t *"), (2, "size_t")],
    # --- Formatting ---
    "printf": [(0, "const char *")],
    "fprintf": [(0, "FILE *"), (1, "const char *")],
    "sprintf": [(0, "char *"), (1, "const char *")],
    "snprintf": [(0, "char *"), (1, "size_t"), (2, "const char *")],
    "vprintf": [(0, "const char *"), (1, "va_list")],
    "vfprintf": [(0, "FILE *"), (1, "const char *"), (2, "va_list")],
    "vsprintf": [(0, "char *"), (1, "const char *"), (2, "va_list")],
    "vsnprintf": [(0, "char *"), (1, "size_t"), (2, "const char *"), (3, "va_list")],
    "sscanf": [(0, "const char *"), (1, "const char *")],
    "scanf": [(0, "const char *")],
    "fscanf": [(0, "FILE *"), (1, "const char *")],
    "puts": [(0, "const char *")],
    "fputs": [(0, "const char *"), (1, "FILE *")],
    "fgets": [(0, "char *"), (1, "int"), (2, "FILE *")],
    "getc": [(0, "FILE *")],
    "fgetc": [(0, "FILE *")],
    "putc": [(0, "int"), (1, "FILE *")],
    "fputc": [(0, "int"), (1, "FILE *")],
    "ungetc": [(0, "int"), (1, "FILE *")],
    "perror": [(0, "const char *")],
    # --- File I/O ---
    "fopen": [(0, "const char *"), (1, "const char *")],
    "fclose": [(0, "FILE *")],
    "fread": [(0, "void *"), (1, "size_t"), (2, "size_t"), (3, "FILE *")],
    "fwrite": [(0, "const void *"), (1, "size_t"), (2, "size_t"), (3, "FILE *")],
    "fseek": [(0, "FILE *"), (1, "long"), (2, "int")],
    "ftell": [(0, "FILE *")],
    "fflush": [(0, "FILE *")],
    "rewind": [(0, "FILE *")],
    "feof": [(0, "FILE *")],
    "ferror": [(0, "FILE *")],
    "clearerr": [(0, "FILE *")],
    "fileno": [(0, "FILE *")],
    "fdopen": [(0, "int"), (1, "const char *")],
    "freopen": [(0, "const char *"), (1, "const char *"), (2, "FILE *")],
    "tmpfile": [],
    "tmpnam": [(0, "char *")],
    "setbuf": [(0, "FILE *"), (1, "char *")],
    "setvbuf": [(0, "FILE *"), (1, "char *"), (2, "int"), (3, "size_t")],
    # --- Low-level I/O ---
    "open": [(0, "const char *"), (1, "int"), (2, "mode_t")],
    "close": [(0, "int")],
    "read": [(0, "int"), (1, "void *"), (2, "size_t")],
    "write": [(0, "int"), (1, "const void *"), (2, "size_t")],
    "lseek": [(0, "int"), (1, "off_t"), (2, "int")],
    "pread": [(0, "int"), (1, "void *"), (2, "size_t"), (3, "off_t")],
    "pwrite": [(0, "int"), (1, "const void *"), (2, "size_t"), (3, "off_t")],
    "dup": [(0, "int")],
    "dup2": [(0, "int"), (1, "int")],
    "pipe": [(0, "int *")],
    "fcntl": [(0, "int"), (1, "int")],
    "ioctl": [(0, "int"), (1, "unsigned long")],
    "stat": [(0, "const char *"), (1, "struct stat *")],
    "fstat": [(0, "int"), (1, "struct stat *")],
    "lstat": [(0, "const char *"), (1, "struct stat *")],
    "access": [(0, "const char *"), (1, "int")],
    "chmod": [(0, "const char *"), (1, "mode_t")],
    "chown": [(0, "const char *"), (1, "uid_t"), (2, "gid_t")],
    "mkdir": [(0, "const char *"), (1, "mode_t")],
    "rmdir": [(0, "const char *")],
    "unlink": [(0, "const char *")],
    "rename": [(0, "const char *"), (1, "const char *")],
    "link": [(0, "const char *"), (1, "const char *")],
    "symlink": [(0, "const char *"), (1, "const char *")],
    "readlink": [(0, "const char *"), (1, "char *"), (2, "size_t")],
    "realpath": [(0, "const char *"), (1, "char *")],
    "truncate": [(0, "const char *"), (1, "off_t")],
    "ftruncate": [(0, "int"), (1, "off_t")],
    "opendir": [(0, "const char *")],
    "closedir": [(0, "DIR *")],
    "chdir": [(0, "const char *")],
    "getcwd": [(0, "char *"), (1, "size_t")],
    # --- Conversion ---
    "atoi": [(0, "const char *")],
    "atol": [(0, "const char *")],
    "atof": [(0, "const char *")],
    "strtol": [(0, "const char *"), (1, "char **"), (2, "int")],
    "strtoul": [(0, "const char *"), (1, "char **"), (2, "int")],
    "strtoll": [(0, "const char *"), (1, "char **"), (2, "int")],
    "strtoull": [(0, "const char *"), (1, "char **"), (2, "int")],
    "strtod": [(0, "const char *"), (1, "char **")],
    "strtof": [(0, "const char *"), (1, "char **")],
    # --- Network ---
    "socket": [(0, "int"), (1, "int"), (2, "int")],
    "bind": [(0, "int"), (1, "const struct sockaddr *"), (2, "socklen_t")],
    "listen": [(0, "int"), (1, "int")],
    "accept": [(0, "int"), (1, "struct sockaddr *"), (2, "socklen_t *")],
    "connect": [(0, "int"), (1, "const struct sockaddr *"), (2, "socklen_t")],
    "send": [(0, "int"), (1, "const void *"), (2, "size_t"), (3, "int")],
    "recv": [(0, "int"), (1, "void *"), (2, "size_t"), (3, "int")],
    "sendto": [(0, "int"), (1, "const void *"), (2, "size_t"), (3, "int"),
               (4, "const struct sockaddr *"), (5, "socklen_t")],
    "recvfrom": [(0, "int"), (1, "void *"), (2, "size_t"), (3, "int"),
                 (4, "struct sockaddr *"), (5, "socklen_t *")],
    "sendmsg": [(0, "int"), (1, "const struct msghdr *"), (2, "int")],
    "recvmsg": [(0, "int"), (1, "struct msghdr *"), (2, "int")],
    "setsockopt": [(0, "int"), (1, "int"), (2, "int"), (3, "const void *"), (4, "socklen_t")],
    "getsockopt": [(0, "int"), (1, "int"), (2, "int"), (3, "void *"), (4, "socklen_t *")],
    "shutdown": [(0, "int"), (1, "int")],
    "select": [(0, "int"), (1, "fd_set *"), (2, "fd_set *"), (3, "fd_set *"),
               (4, "struct timeval *")],
    "poll": [(0, "struct pollfd *"), (1, "nfds_t"), (2, "int")],
    "epoll_create": [(0, "int")],
    "epoll_ctl": [(0, "int"), (1, "int"), (2, "int"), (3, "struct epoll_event *")],
    "epoll_wait": [(0, "int"), (1, "struct epoll_event *"), (2, "int"), (3, "int")],
    "getaddrinfo": [(0, "const char *"), (1, "const char *"),
                    (2, "const struct addrinfo *"), (3, "struct addrinfo **")],
    "freeaddrinfo": [(0, "struct addrinfo *")],
    "inet_pton": [(0, "int"), (1, "const char *"), (2, "void *")],
    "inet_ntop": [(0, "int"), (1, "const void *"), (2, "char *"), (3, "socklen_t")],
    "htons": [(0, "uint16_t")],
    "ntohs": [(0, "uint16_t")],
    "htonl": [(0, "uint32_t")],
    "ntohl": [(0, "uint32_t")],
    "gethostbyname": [(0, "const char *")],
    "getpeername": [(0, "int"), (1, "struct sockaddr *"), (2, "socklen_t *")],
    "getsockname": [(0, "int"), (1, "struct sockaddr *"), (2, "socklen_t *")],
    # --- Process ---
    "execve": [(0, "const char *"), (1, "char *const *"), (2, "char *const *")],
    "execvp": [(0, "const char *"), (1, "char *const *")],
    "execl": [(0, "const char *"), (1, "const char *")],
    "execlp": [(0, "const char *"), (1, "const char *")],
    "waitpid": [(0, "pid_t"), (1, "int *"), (2, "int")],
    "kill": [(0, "pid_t"), (1, "int")],
    "signal": [(0, "int"), (1, "sighandler_t")],
    "sigaction": [(0, "int"), (1, "const struct sigaction *"), (2, "struct sigaction *")],
    "exit": [(0, "int")],
    "_exit": [(0, "int")],
    "system": [(0, "const char *")],
    "popen": [(0, "const char *"), (1, "const char *")],
    "pclose": [(0, "FILE *")],
    "setenv": [(0, "const char *"), (1, "const char *"), (2, "int")],
    "getenv": [(0, "const char *")],
    "unsetenv": [(0, "const char *")],
    # --- Thread ---
    "pthread_create": [(0, "pthread_t *"), (1, "const pthread_attr_t *"),
                       (2, "void *(*)(void *)"), (3, "void *")],
    "pthread_join": [(0, "pthread_t"), (1, "void **")],
    "pthread_mutex_init": [(0, "pthread_mutex_t *"), (1, "const pthread_mutexattr_t *")],
    "pthread_mutex_lock": [(0, "pthread_mutex_t *")],
    "pthread_mutex_unlock": [(0, "pthread_mutex_t *")],
    "pthread_mutex_destroy": [(0, "pthread_mutex_t *")],
    "pthread_cond_init": [(0, "pthread_cond_t *"), (1, "const pthread_condattr_t *")],
    "pthread_cond_wait": [(0, "pthread_cond_t *"), (1, "pthread_mutex_t *")],
    "pthread_cond_signal": [(0, "pthread_cond_t *")],
    "pthread_cond_broadcast": [(0, "pthread_cond_t *")],
    "pthread_rwlock_rdlock": [(0, "pthread_rwlock_t *")],
    "pthread_rwlock_wrlock": [(0, "pthread_rwlock_t *")],
    "pthread_rwlock_unlock": [(0, "pthread_rwlock_t *")],
    "sem_init": [(0, "sem_t *"), (1, "int"), (2, "unsigned int")],
    "sem_wait": [(0, "sem_t *")],
    "sem_post": [(0, "sem_t *")],
    "sem_destroy": [(0, "sem_t *")],
    # --- Dynamic loading ---
    "dlopen": [(0, "const char *"), (1, "int")],
    "dlsym": [(0, "void *"), (1, "const char *")],
    "dlclose": [(0, "void *")],
    "dlerror": [],
    # --- Time ---
    "time": [(0, "time_t *")],
    "gettimeofday": [(0, "struct timeval *"), (1, "struct timezone *")],
    "clock_gettime": [(0, "clockid_t"), (1, "struct timespec *")],
    "sleep": [(0, "unsigned int")],
    "usleep": [(0, "useconds_t")],
    "nanosleep": [(0, "const struct timespec *"), (1, "struct timespec *")],
    "localtime": [(0, "const time_t *")],
    "gmtime": [(0, "const time_t *")],
    "mktime": [(0, "struct tm *")],
    "strftime": [(0, "char *"), (1, "size_t"), (2, "const char *"), (3, "const struct tm *")],
    # --- Math ---
    "abs": [(0, "int")],
    "labs": [(0, "long")],
    "fabs": [(0, "double")],
    "fabsf": [(0, "float")],
    "sqrt": [(0, "double")],
    "sqrtf": [(0, "float")],
    "pow": [(0, "double"), (1, "double")],
    "powf": [(0, "float"), (1, "float")],
    "ceil": [(0, "double")],
    "ceilf": [(0, "float")],
    "floor": [(0, "double")],
    "floorf": [(0, "float")],
    "round": [(0, "double")],
    "roundf": [(0, "float")],
    "log": [(0, "double")],
    "logf": [(0, "float")],
    "log2": [(0, "double")],
    "log10": [(0, "double")],
    "exp": [(0, "double")],
    "expf": [(0, "float")],
    "sin": [(0, "double")],
    "sinf": [(0, "float")],
    "cos": [(0, "double")],
    "cosf": [(0, "float")],
    "tan": [(0, "double")],
    "tanf": [(0, "float")],
    "atan2": [(0, "double"), (1, "double")],
    "atan2f": [(0, "float"), (1, "float")],
    "fmod": [(0, "double"), (1, "double")],
    "fmodf": [(0, "float"), (1, "float")],
    # --- Sort / Search ---
    "qsort": [(0, "void *"), (1, "size_t"), (2, "size_t"), (3, "int (*)(const void *, const void *)")],
    "bsearch": [(0, "const void *"), (1, "const void *"), (2, "size_t"), (3, "size_t"),
                (4, "int (*)(const void *, const void *)")],
    # --- Error ---
    "strerror": [(0, "int")],
    # --- OpenSSL ---
    "SSL_CTX_new": [(0, "const SSL_METHOD *")],
    "SSL_new": [(0, "SSL_CTX *")],
    "SSL_set_fd": [(0, "SSL *"), (1, "int")],
    "SSL_connect": [(0, "SSL *")],
    "SSL_accept": [(0, "SSL *")],
    "SSL_read": [(0, "SSL *"), (1, "void *"), (2, "int")],
    "SSL_write": [(0, "SSL *"), (1, "const void *"), (2, "int")],
    "SSL_shutdown": [(0, "SSL *")],
    "SSL_free": [(0, "SSL *")],
    "SSL_CTX_free": [(0, "SSL_CTX *")],
    "SSL_get_error": [(0, "const SSL *"), (1, "int")],
    "EVP_EncryptInit_ex": [(0, "EVP_CIPHER_CTX *"), (1, "const EVP_CIPHER *"),
                           (2, "ENGINE *"), (3, "const unsigned char *"),
                           (4, "const unsigned char *")],
    "EVP_EncryptUpdate": [(0, "EVP_CIPHER_CTX *"), (1, "unsigned char *"),
                          (2, "int *"), (3, "const unsigned char *"), (4, "int")],
    "EVP_DecryptInit_ex": [(0, "EVP_CIPHER_CTX *"), (1, "const EVP_CIPHER *"),
                           (2, "ENGINE *"), (3, "const unsigned char *"),
                           (4, "const unsigned char *")],
    "EVP_DecryptUpdate": [(0, "EVP_CIPHER_CTX *"), (1, "unsigned char *"),
                          (2, "int *"), (3, "const unsigned char *"), (4, "int")],
    "EVP_DigestInit_ex": [(0, "EVP_MD_CTX *"), (1, "const EVP_MD *"), (2, "ENGINE *")],
    "EVP_DigestUpdate": [(0, "EVP_MD_CTX *"), (1, "const void *"), (2, "size_t")],
    "EVP_DigestFinal_ex": [(0, "EVP_MD_CTX *"), (1, "unsigned char *"), (2, "unsigned int *")],
    "RAND_bytes": [(0, "unsigned char *"), (1, "int")],
    "HMAC": [(0, "const EVP_MD *"), (1, "const void *"), (2, "int"),
             (3, "const unsigned char *"), (4, "size_t"),
             (5, "unsigned char *"), (6, "unsigned int *")],
    "SHA256_Init": [(0, "SHA256_CTX *")],
    "SHA256_Update": [(0, "SHA256_CTX *"), (1, "const void *"), (2, "size_t")],
    "SHA256_Final": [(0, "unsigned char *"), (1, "SHA256_CTX *")],
    "MD5_Init": [(0, "MD5_CTX *")],
    "MD5_Update": [(0, "MD5_CTX *"), (1, "const void *"), (2, "unsigned long")],
    "MD5_Final": [(0, "unsigned char *"), (1, "MD5_CTX *")],
    "RSA_public_encrypt": [(0, "int"), (1, "const unsigned char *"),
                           (2, "unsigned char *"), (3, "RSA *"), (4, "int")],
    "RSA_private_decrypt": [(0, "int"), (1, "const unsigned char *"),
                            (2, "unsigned char *"), (3, "RSA *"), (4, "int")],
    "AES_set_encrypt_key": [(0, "const unsigned char *"), (1, "int"), (2, "AES_KEY *")],
    "AES_set_decrypt_key": [(0, "const unsigned char *"), (1, "int"), (2, "AES_KEY *")],
    "AES_encrypt": [(0, "const unsigned char *"), (1, "unsigned char *"), (2, "const AES_KEY *")],
    "AES_decrypt": [(0, "const unsigned char *"), (1, "unsigned char *"), (2, "const AES_KEY *")],
    # --- zlib ---
    "compress": [(0, "Bytef *"), (1, "uLongf *"), (2, "const Bytef *"), (3, "uLong")],
    "uncompress": [(0, "Bytef *"), (1, "uLongf *"), (2, "const Bytef *"), (3, "uLong")],
    "deflateInit": [(0, "z_streamp"), (1, "int")],
    "deflate": [(0, "z_streamp"), (1, "int")],
    "deflateEnd": [(0, "z_streamp")],
    "inflateInit": [(0, "z_streamp")],
    "inflate": [(0, "z_streamp"), (1, "int")],
    "inflateEnd": [(0, "z_streamp")],
    "crc32": [(0, "uLong"), (1, "const Bytef *"), (2, "uInt")],
    # --- SQLite ---
    "sqlite3_open": [(0, "const char *"), (1, "sqlite3 **")],
    "sqlite3_close": [(0, "sqlite3 *")],
    "sqlite3_exec": [(0, "sqlite3 *"), (1, "const char *"), (2, "sqlite3_callback"),
                     (3, "void *"), (4, "char **")],
    "sqlite3_prepare_v2": [(0, "sqlite3 *"), (1, "const char *"), (2, "int"),
                           (3, "sqlite3_stmt **"), (4, "const char **")],
    "sqlite3_step": [(0, "sqlite3_stmt *")],
    "sqlite3_finalize": [(0, "sqlite3_stmt *")],
    "sqlite3_bind_int": [(0, "sqlite3_stmt *"), (1, "int"), (2, "int")],
    "sqlite3_bind_text": [(0, "sqlite3_stmt *"), (1, "int"), (2, "const char *"),
                          (3, "int"), (4, "void (*)(void *)")],
    "sqlite3_column_int": [(0, "sqlite3_stmt *"), (1, "int")],
    "sqlite3_column_text": [(0, "sqlite3_stmt *"), (1, "int")],
    "sqlite3_errmsg": [(0, "sqlite3 *")],
    # --- libcurl ---
    "curl_easy_init": [],
    "curl_easy_setopt": [(0, "CURL *"), (1, "CURLoption")],
    "curl_easy_perform": [(0, "CURL *")],
    "curl_easy_cleanup": [(0, "CURL *")],
    "curl_easy_getinfo": [(0, "CURL *"), (1, "CURLINFO")],
    "curl_global_init": [(0, "long")],
    # --- GLib ---
    "g_malloc": [(0, "gsize")],
    "g_free": [(0, "gpointer")],
    "g_strdup": [(0, "const gchar *")],
    "g_strndup": [(0, "const gchar *"), (1, "gsize")],
    "g_string_new": [(0, "const gchar *")],
    "g_string_free": [(0, "GString *"), (1, "gboolean")],
    "g_list_append": [(0, "GList *"), (1, "gpointer")],
    "g_hash_table_new": [(0, "GHashFunc"), (1, "GEqualFunc")],
    "g_hash_table_insert": [(0, "GHashTable *"), (1, "gpointer"), (2, "gpointer")],
    "g_hash_table_lookup": [(0, "GHashTable *"), (1, "gconstpointer")],
    # --- X11 / Wayland ---
    "XOpenDisplay": [(0, "const char *")],
    "XCloseDisplay": [(0, "Display *")],
    "XCreateWindow": [(0, "Display *")],
    # --- setjmp/longjmp ---
    "setjmp": [(0, "jmp_buf")],
    "longjmp": [(0, "jmp_buf"), (1, "int")],
    # --- Regex ---
    "regcomp": [(0, "regex_t *"), (1, "const char *"), (2, "int")],
    "regexec": [(0, "const regex_t *"), (1, "const char *"), (2, "size_t"),
                (3, "regmatch_t *"), (4, "int")],
    "regfree": [(0, "regex_t *")],
    # --- iconv ---
    "iconv_open": [(0, "const char *"), (1, "const char *")],
    "iconv": [(0, "iconv_t"), (1, "char **"), (2, "size_t *"), (3, "char **"), (4, "size_t *")],
    "iconv_close": [(0, "iconv_t")],
}

# Mach-O underscore prefix'li versiyonlari otomatik olustur
_API_PARAM_TYPES_PREFIXED: dict[str, list[tuple[int, str]]] = {
    f"_{k}": v for k, v in _API_PARAM_TYPES.items()
}
_API_PARAM_TYPES.update(_API_PARAM_TYPES_PREFIXED)


# ---------------------------------------------------------------------------
# Bilinen fonksiyon donus tipleri
# ---------------------------------------------------------------------------
_RETURN_TYPES: dict[str, str] = {
    # Memory
    "malloc": "void *", "calloc": "void *", "realloc": "void *",
    "mmap": "void *", "aligned_alloc": "void *",
    # String
    "strlen": "size_t", "strcmp": "int", "strncmp": "int",
    "strcpy": "char *", "strncpy": "char *", "strcat": "char *",
    "strstr": "char *", "strchr": "char *", "strrchr": "char *",
    "strdup": "char *", "strtok": "char *", "strtok_r": "char *",
    "stpcpy": "char *", "stpncpy": "char *", "strpbrk": "char *",
    "strsep": "char *", "strerror": "char *",
    "memcpy": "void *", "memmove": "void *", "memset": "void *",
    "memchr": "void *", "memcmp": "int",
    # File I/O
    "fopen": "FILE *", "fdopen": "FILE *", "freopen": "FILE *",
    "tmpfile": "FILE *", "popen": "FILE *",
    "open": "int", "close": "int", "read": "ssize_t", "write": "ssize_t",
    "lseek": "off_t", "ftell": "long", "feof": "int", "ferror": "int",
    "fread": "size_t", "fwrite": "size_t", "fflush": "int",
    "fclose": "int", "fseek": "int", "fileno": "int",
    "access": "int", "stat": "int", "fstat": "int", "lstat": "int",
    "mkdir": "int", "rmdir": "int", "unlink": "int", "rename": "int",
    "opendir": "DIR *", "readdir": "struct dirent *",
    "getcwd": "char *", "realpath": "char *",
    # Conversion
    "atoi": "int", "atol": "long", "atof": "double",
    "strtol": "long", "strtoul": "unsigned long",
    "strtoll": "long long", "strtoull": "unsigned long long",
    "strtod": "double", "strtof": "float",
    # Network
    "socket": "int", "bind": "int", "listen": "int", "accept": "int",
    "connect": "int", "send": "ssize_t", "recv": "ssize_t",
    "sendto": "ssize_t", "recvfrom": "ssize_t",
    "select": "int", "poll": "int",
    "htons": "uint16_t", "ntohs": "uint16_t",
    "htonl": "uint32_t", "ntohl": "uint32_t",
    "inet_pton": "int", "inet_ntop": "const char *",
    "gethostbyname": "struct hostent *",
    # Process
    "fork": "pid_t", "getpid": "pid_t", "getppid": "pid_t",
    "waitpid": "pid_t", "system": "int", "execve": "int",
    # Thread
    "pthread_create": "int", "pthread_join": "int",
    "pthread_mutex_init": "int", "pthread_mutex_lock": "int",
    "pthread_mutex_unlock": "int",
    # Dynamic loading
    "dlopen": "void *", "dlsym": "void *", "dlclose": "int",
    "dlerror": "char *",
    # Time
    "time": "time_t", "clock": "clock_t",
    "localtime": "struct tm *", "gmtime": "struct tm *",
    "mktime": "time_t",
    # Math
    "abs": "int", "labs": "long", "fabs": "double", "fabsf": "float",
    "sqrt": "double", "sqrtf": "float", "pow": "double", "powf": "float",
    "ceil": "double", "ceilf": "float", "floor": "double", "floorf": "float",
    "round": "double", "roundf": "float",
    "log": "double", "logf": "float", "log2": "double", "log10": "double",
    "exp": "double", "expf": "float",
    "sin": "double", "sinf": "float", "cos": "double", "cosf": "float",
    "tan": "double", "tanf": "float",
    "atan2": "double", "atan2f": "float",
    # Misc
    "getenv": "char *", "tmpnam": "char *",
    # OpenSSL
    "SSL_CTX_new": "SSL_CTX *", "SSL_new": "SSL *",
    "EVP_CIPHER_CTX_new": "EVP_CIPHER_CTX *", "EVP_MD_CTX_new": "EVP_MD_CTX *",
    "BIO_new": "BIO *",
    # SQLite
    "sqlite3_errmsg": "const char *",
    # libcurl
    "curl_easy_init": "CURL *",
}
# Underscore-prefixed
_RETURN_TYPES.update({f"_{k}": v for k, v in _RETURN_TYPES.items()})


# ---------------------------------------------------------------------------
# Pre-compiled regex'ler
# ---------------------------------------------------------------------------

# Ghidra generic variable pattern
_GENERIC_VAR_RE = re.compile(
    r"^(?:param_\d+|local_[0-9a-fA-F]+|[a-z]Var\d+|in_stack_[0-9a-fA-F]+|"
    r"uVar\d+|iVar\d+|lVar\d+|cVar\d+|sVar\d+|bVar\d+|fVar\d+|dVar\d+|"
    r"pVar\d+|ppVar\d+|pvVar\d+|auVar\d+|extraout_\w+|in_\w+)$"
)

# Fonksiyon cagrisi: func(arg1, arg2, ...)
_CALL_RE = re.compile(r"\b(\w+)\s*\(([^)]*)\)")

# Dongu: for (var = init; var cmp N; var++)
_FOR_LOOP_RE = re.compile(
    r"for\s*\(\s*(\w+)\s*=\s*[^;]+;\s*\w+\s*[<>!=]+\s*(\w+)\s*;\s*(\w+)\s*\+\+"
)
# while (*var) -- string iteration
_WHILE_DEREF_RE = re.compile(r"while\s*\(\s*\*\s*(\w+)\s*\)")
# while (var != NULL / var != 0)
_WHILE_NOT_NULL_RE = re.compile(r"while\s*\(\s*(\w+)\s*!=\s*(?:NULL|0|0x0)\s*\)")

# Operatorler
_INCREMENT_RE = re.compile(r"\b(\w+)\s*\+\+|\+\+\s*(\w+)")
_DEREF_RE = re.compile(r"(?<!\w)\*\s*(\w+)(?:\s*[;=,)\]])")
_ARROW_RE = re.compile(r"(\w+)\s*->\s*\w+")
_ARRAY_RE = re.compile(r"(\w+)\s*\[\s*(?:\w+|\d+)\s*\]")
_ADDR_OF_RE = re.compile(r"&\s*(\w+)(?:\s*[,)\]])")
_BITWISE_MASK_RE = re.compile(r"(\w+)\s*&\s*0x([0-9a-fA-F]+)")
_SHIFT_RE = re.compile(r"(\w+)\s*(?:<<|>>)\s*(\d+)")

# Karsilastirma
_CMP_NULL_RE = re.compile(r"(\w+)\s*[!=]=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(?:NULL|0x0)\b")
_CMP_CHAR_RE = re.compile(r"(\w+)\s*[!=]=\s*'\\?.'")
_CMP_ZERO_RE = re.compile(r"(\w+)\s*[<>!=]=?\s*0\b(?!x)")
_CMP_NEGATIVE_RE = re.compile(r"(\w+)\s*<\s*0\b")

# Atama
_ASSIGN_MALLOC_RE = re.compile(r"(\w+)\s*=\s*(?:\(\s*\w[\w\s]*\*\s*\)\s*)?(?:malloc|calloc|realloc)\s*\(")
_ASSIGN_FOPEN_RE = re.compile(r"(\w+)\s*=\s*(?:_)?fopen\s*\(")
_ASSIGN_SOCKET_RE = re.compile(r"(\w+)\s*=\s*(?:_)?socket\s*\(")
_ASSIGN_STRDUP_RE = re.compile(r"(\w+)\s*=\s*(?:_)?strdup\s*\(")
_ASSIGN_DLOPEN_RE = re.compile(r"(\w+)\s*=\s*(?:_)?dlopen\s*\(")
_ASSIGN_OPENDIR_RE = re.compile(r"(\w+)\s*=\s*(?:_)?opendir\s*\(")
_ASSIGN_FDOPEN_RE = re.compile(r"(\w+)\s*=\s*(?:_)?fdopen\s*\(")
_ASSIGN_POPEN_RE = re.compile(r"(\w+)\s*=\s*(?:_)?popen\s*\(")
_ASSIGN_TMPFILE_RE = re.compile(r"(\w+)\s*=\s*(?:_)?tmpfile\s*\(")
# var = known_func(...) genel pattern
_ASSIGN_FUNC_RE = re.compile(r"(\w+)\s*=\s*(\w+)\s*\(")

# Explicit cast
_EXPLICIT_CAST_RE = re.compile(
    r"(\w+)\s*=\s*\(\s*([a-zA-Z_][\w\s]*\*?)\s*\)"
)
# *(TYPE *)(var + offset) -- indirect tipler
_CAST_DEREF_RE = re.compile(
    r"\*\(\s*(?P<type>[a-zA-Z_][\w\s]*\*)\s*\)\s*\(\s*(?P<var>\w+)"
)

# String literal atamasi
_STRING_LITERAL_RE = re.compile(r'(\w+)\s*=\s*"[^"]*"')

# sizeof(var)
_SIZEOF_RE = re.compile(r"sizeof\s*\(\s*(\w+)\s*\)")

# Ghidra bildirim: TYPE varname;
_DECL_RE = re.compile(
    r"^\s*(?P<type>undefined[1248]?|long\s*long|unsigned\s+long|unsigned\s+int|"
    r"unsigned\s+short|unsigned\s+char|long|int|short|char|uint\d+_t|int\d+_t|"
    r"size_t|ssize_t|off_t|pid_t|uid_t|gid_t|time_t|clock_t|"
    r"float|double|void|bool|_Bool|ulong|uint|byte|ushort|"
    r"BOOL|DWORD|WORD|BYTE|HANDLE|LPSTR|LPCSTR|LPWSTR|LPCWSTR|"
    r"HMODULE|HINSTANCE|HWND|HDC|HBITMAP|HFONT|HBRUSH|HPEN|"
    r"SOCKET|WSADATA|sockaddr_in|sockaddr|"
    r"FILE|DIR|"
    r"(?:[a-zA-Z_]\w*(?:\s*\*)+))"
    r"(?:\s*\*)*\s+"
    r"(?P<var>\w+)\s*[;=]",
    re.MULTILINE,
)

# Float literal
_FLOAT_LITERAL_RE = re.compile(r"(\w+)\s*=\s*[^;]*\b(\d+\.\d+(?:[eE][+\-]?\d+)?)\b")

# Return statement: return VAR;
_RETURN_VAR_RE = re.compile(r"\breturn\s+(\w+)\s*;")

# Fonksiyon signature -- donus tipini cikar
_FUNC_SIGNATURE_RE = re.compile(
    r"^\s*(?P<ret_type>[a-zA-Z_][\w\s]*\*?)\s+(?P<fname>\w+)\s*\(",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Ghidra tip iyilestirme: undefined -> gercek tip eslestirme
# ---------------------------------------------------------------------------
_GHIDRA_TYPE_IMPROVEMENTS: dict[str, dict[str, str]] = {
    # tag -> {ghidra_type -> improved_type}
    "string_func_arg": {
        "undefined8": "char *", "undefined4": "char *", "long": "char *",
        "undefined": "char *",
    },
    "pointer_deref": {
        "undefined8": "void *", "long": "void *",
    },
    "array_access": {
        "undefined8": "void *", "long": "void *",
    },
    "pointer_arithmetic": {
        "undefined8": "void *", "long": "void *",
    },
    "boolean_test": {
        "undefined4": "int", "undefined8": "int", "undefined": "bool",
    },
    "alloc_result": {
        "undefined8": "void *", "long": "void *", "undefined4": "void *",
    },
    "bitwise_op": {
        "undefined8": "uint64_t", "undefined4": "uint32_t",
        "undefined2": "uint16_t", "undefined1": "uint8_t",
        "long": "uint64_t", "int": "uint32_t",
    },
    "comparison": {
        "undefined4": "int", "undefined8": "long", "undefined2": "short",
    },
    "arithmetic": {
        "undefined4": "int", "undefined8": "long",
    },
    "float_literal_assign": {
        "undefined8": "double", "undefined4": "float", "long": "double",
    },
}


# =====================================================================
# Ana sinif
# =====================================================================


class XTrideTyper:
    """N-gram tabanli tip inference (XTRIDE yaklasimi).

    Decompiled C kodundan degisken tiplerini tahmin eder. Birden fazla
    n-gram kaynagini birlestirir; en yuksek guvenli kaynagi secer.

    Attributes:
        _api_types: API parametre tip DB'si.
        _return_types: Fonksiyon donus tip DB'si.
        stats: Istatistik sayaclari.
    """

    def __init__(self) -> None:
        self._api_types = _API_PARAM_TYPES
        self._return_types = _RETURN_TYPES
        self.stats: dict[str, int] = {
            "total_functions": 0,
            "total_inferences": 0,
            "api_param_inferences": 0,
            "return_type_inferences": 0,
            "operator_inferences": 0,
            "loop_inferences": 0,
            "comparison_inferences": 0,
            "assignment_inferences": 0,
            "declaration_inferences": 0,
            "cast_inferences": 0,
        }

    def infer_types(self, func_code: str, func_name: str = "") -> XTrideResult:
        """Fonksiyon kodundan degisken tiplerini tahmin et.

        Args:
            func_code: Ghidra decompiled C fonksiyon kodu.
            func_name: Fonksiyon adi (logging icin).

        Returns:
            XTrideResult: {var_name: TypeInference} eslesmesi.
        """
        self.stats["total_functions"] += 1
        result = XTrideResult(func_name=func_name)

        # Her kaynak icin tahminleri topla, sonra birlesik sonuc uret
        # candidates: var -> [(type, confidence, source, evidence), ...]
        candidates: dict[str, list[tuple[str, float, str, str]]] = {}

        def _add(var: str, typ: str, conf: float, src: str, ev: str = "") -> None:
            if not var or not _GENERIC_VAR_RE.match(var):
                return
            candidates.setdefault(var, []).append((typ, conf, src, ev))

        # 1. API Parametre Tipleri
        self._infer_api_params(func_code, _add)

        # 2. Donus Tipi Atamasi
        self._infer_return_types(func_code, _add)

        # 3. Operator Kaliplari
        self._infer_operators(func_code, _add)

        # 4. Dongu Kaliplari
        self._infer_loops(func_code, _add)

        # 5. Karsilastirma Kaliplari
        self._infer_comparisons(func_code, _add)

        # 6. Atama Kaliplari
        self._infer_assignments(func_code, _add)

        # 7. Explicit Cast
        self._infer_casts(func_code, _add)

        # 8. String Literal
        self._infer_string_literals(func_code, _add)

        # 9. Float Literal
        self._infer_float_literals(func_code, _add)

        # 10. sizeof() kullanimi
        self._infer_sizeof(func_code, _add)

        # Birlestirme: en yuksek confidence'li tahmini sec
        for var, cands in candidates.items():
            if not cands:
                continue
            # Ayni tip ile birden fazla kanit varsa confidence'i biraz artir
            type_counts: dict[str, list[tuple[float, str, str]]] = {}
            for typ, conf, src, ev in cands:
                type_counts.setdefault(typ, []).append((conf, src, ev))

            best_type = ""
            best_conf = 0.0
            best_src = ""
            best_ev = ""
            for typ, entries in type_counts.items():
                # Bayesian log-odds fusion: tum kanit confidence'larini birlestirir
                all_confs = [e[0] for e in entries]
                combined = _bayesian_merge_confidences(all_confs)
                if combined > best_conf:
                    best_conf = combined
                    best_type = typ
                    # En yuksek confidence'li kaniti sec
                    best_entry = max(entries, key=lambda e: e[0])
                    best_src = best_entry[1]
                    best_ev = best_entry[2]

            # Minimum confidence threshold -- tek kaynakli dusuk guvenilirlikli
            # sonuclari filtrele; kanit yetersizse tip atamasini atla
            if best_conf < 0.50:
                continue

            if best_type:
                result.inferences[var] = TypeInference(
                    var_name=var,
                    inferred_type=best_type,
                    confidence=round(best_conf, 3),
                    source=best_src,
                    evidence=best_ev,
                )

        result.total_inferred = len(result.inferences)
        self.stats["total_inferences"] += result.total_inferred
        return result

    # ------------------------------------------------------------------
    # Inference katmanlari
    # ------------------------------------------------------------------

    def _infer_api_params(
        self,
        code: str,
        add: Any,
    ) -> None:
        """API cagrisi parametrelerinden tip cikar."""
        for m in _CALL_RE.finditer(code):
            func_name = m.group(1)
            # Kontrol akis keyword'lerini atla
            if func_name in ("if", "while", "for", "switch", "sizeof", "return",
                             "else", "do", "case", "goto"):
                continue

            type_info = self._api_types.get(func_name)
            if not type_info:
                continue

            args_str = m.group(2)
            args = self._split_args_simple(args_str)

            for param_idx, param_type in type_info:
                if param_idx < len(args):
                    arg = args[param_idx].strip()
                    # Cast'i kaldir: (TYPE)var -> var
                    cast_m = re.match(r"\(\s*\w[\w\s]*\*?\s*\)\s*(\w+)", arg)
                    if cast_m:
                        arg = cast_m.group(1)
                    # Adres operatoru: &var -> var (pointer tipi zaten)
                    if arg.startswith("&"):
                        arg = arg[1:].strip()
                        # &var geciliyorsa, var'in tipi param_type'dan * cikarilmis hali
                        if param_type.endswith("*"):
                            deref_type = param_type.rsplit("*", 1)[0].strip()
                            if deref_type:
                                add(arg, deref_type, CONFIDENCE_API_PARAM, "api_param",
                                    f"&{arg} passed as {param_type} to {func_name}")
                                self.stats["api_param_inferences"] += 1
                                continue
                    add(arg, param_type, CONFIDENCE_API_PARAM, "api_param",
                        f"arg[{param_idx}] of {func_name}")
                    self.stats["api_param_inferences"] += 1

    def _infer_return_types(
        self,
        code: str,
        add: Any,
    ) -> None:
        """var = known_func(...) atamasindan donus tipi cikar."""
        for m in _ASSIGN_FUNC_RE.finditer(code):
            var = m.group(1)
            func_name = m.group(2)
            if func_name in ("if", "while", "for", "switch", "sizeof", "return"):
                continue
            ret_type = self._return_types.get(func_name)
            if ret_type:
                add(var, ret_type, CONFIDENCE_RETURN_TYPE, "return_type",
                    f"return of {func_name}")
                self.stats["return_type_inferences"] += 1

    def _infer_operators(
        self,
        code: str,
        add: Any,
    ) -> None:
        """Operator kullanim pattern'lerinden tip cikar."""
        # var++ / ++var -> integer
        for m in _INCREMENT_RE.finditer(code):
            var = m.group(1) or m.group(2)
            if var:
                add(var, "int", CONFIDENCE_OPERATOR, "operator", "increment (++)")
                self.stats["operator_inferences"] += 1

        # *var -> pointer
        for m in _DEREF_RE.finditer(code):
            var = m.group(1)
            add(var, "void *", CONFIDENCE_OPERATOR, "operator", "dereference (*)")
            self.stats["operator_inferences"] += 1

        # var->field -> struct pointer
        for m in _ARROW_RE.finditer(code):
            var = m.group(1)
            add(var, "void *", CONFIDENCE_OPERATOR, "operator", "arrow (->)")
            self.stats["operator_inferences"] += 1

        # var[idx] -> array/pointer
        for m in _ARRAY_RE.finditer(code):
            var = m.group(1)
            add(var, "void *", CONFIDENCE_OPERATOR, "operator", "array access ([])")
            self.stats["operator_inferences"] += 1

        # &var -- var'in adresi aliniyorsa, var kendisi pointer degil
        # (genellikle bir struct/int/etc adresi)
        # Bu cok belirsiz, atliyoruz.

        # var & 0xFF -> uint8_t, var & 0xFFFF -> uint16_t, etc
        for m in _BITWISE_MASK_RE.finditer(code):
            var = m.group(1)
            mask_hex = m.group(2)
            mask_val = int(mask_hex, 16)
            if mask_val <= 0xFF:
                add(var, "uint8_t", CONFIDENCE_BITWISE, "operator", f"mask & 0x{mask_hex}")
            elif mask_val <= 0xFFFF:
                add(var, "uint16_t", CONFIDENCE_BITWISE, "operator", f"mask & 0x{mask_hex}")
            elif mask_val <= 0xFFFFFFFF:
                add(var, "uint32_t", CONFIDENCE_BITWISE, "operator", f"mask & 0x{mask_hex}")
            else:
                add(var, "uint64_t", CONFIDENCE_BITWISE, "operator", f"mask & 0x{mask_hex}")
            self.stats["operator_inferences"] += 1

        # var << N / var >> N -> unsigned int
        for m in _SHIFT_RE.finditer(code):
            var = m.group(1)
            shift = int(m.group(2))
            if shift >= 32:
                add(var, "uint64_t", CONFIDENCE_BITWISE, "operator", f"shift by {shift}")
            else:
                add(var, "uint32_t", CONFIDENCE_BITWISE, "operator", f"shift by {shift}")
            self.stats["operator_inferences"] += 1

    def _infer_loops(
        self,
        code: str,
        add: Any,
    ) -> None:
        """Dongu pattern'lerinden tip cikar."""
        # for (i = 0; i < N; i++) -> i: int, N: size_t
        for m in _FOR_LOOP_RE.finditer(code):
            init_var = m.group(1)
            limit_var = m.group(2)
            inc_var = m.group(3)
            # i = init_var = inc_var (genellikle ayni)
            add(init_var, "int", CONFIDENCE_LOOP, "loop", "for-loop init")
            add(inc_var, "int", CONFIDENCE_LOOP, "loop", "for-loop increment")
            # limit degiskeni -- size veya length olabilir
            if _GENERIC_VAR_RE.match(limit_var):
                add(limit_var, "size_t", CONFIDENCE_LOOP, "loop", "for-loop limit")
            self.stats["loop_inferences"] += 1

        # while (*p) -> p: char * (string iteration)
        for m in _WHILE_DEREF_RE.finditer(code):
            var = m.group(1)
            add(var, "char *", CONFIDENCE_LOOP, "loop", "while(*p) string iteration")
            self.stats["loop_inferences"] += 1

        # while (p != NULL) -> p: pointer
        for m in _WHILE_NOT_NULL_RE.finditer(code):
            var = m.group(1)
            add(var, "void *", CONFIDENCE_LOOP, "loop", "while(p != NULL)")
            self.stats["loop_inferences"] += 1

    def _infer_comparisons(
        self,
        code: str,
        add: Any,
    ) -> None:
        """Karsilastirma pattern'lerinden tip cikar."""
        # var == NULL / var != NULL -> pointer
        for m in _CMP_NULL_RE.finditer(code):
            var = m.group(1)
            add(var, "void *", CONFIDENCE_COMPARISON, "comparison", "NULL comparison")
            self.stats["comparison_inferences"] += 1

        # var == 'x' / var != '\0' -> char
        for m in _CMP_CHAR_RE.finditer(code):
            var = m.group(1)
            add(var, "char", CONFIDENCE_COMPARISON, "comparison", "char literal comparison")
            self.stats["comparison_inferences"] += 1

        # var < 0 -> signed int (ssize_t, int)
        for m in _CMP_NEGATIVE_RE.finditer(code):
            var = m.group(1)
            add(var, "int", CONFIDENCE_COMPARISON, "comparison", "negative comparison (< 0)")
            self.stats["comparison_inferences"] += 1

    def _infer_assignments(
        self,
        code: str,
        add: Any,
    ) -> None:
        """Atama pattern'lerinden tip cikar."""
        # var = malloc(...) -> void *
        for m in _ASSIGN_MALLOC_RE.finditer(code):
            var = m.group(1)
            add(var, "void *", CONFIDENCE_ASSIGNMENT, "assignment", "malloc/calloc/realloc result")
            self.stats["assignment_inferences"] += 1

        # var = fopen(...) -> FILE *
        for m in _ASSIGN_FOPEN_RE.finditer(code):
            var = m.group(1)
            add(var, "FILE *", CONFIDENCE_ASSIGNMENT, "assignment", "fopen result")
            self.stats["assignment_inferences"] += 1

        # var = socket(...) -> int
        for m in _ASSIGN_SOCKET_RE.finditer(code):
            var = m.group(1)
            add(var, "int", CONFIDENCE_ASSIGNMENT, "assignment", "socket result")
            self.stats["assignment_inferences"] += 1

        # var = strdup(...) -> char *
        for m in _ASSIGN_STRDUP_RE.finditer(code):
            var = m.group(1)
            add(var, "char *", CONFIDENCE_ASSIGNMENT, "assignment", "strdup result")
            self.stats["assignment_inferences"] += 1

        # var = dlopen(...) -> void *
        for m in _ASSIGN_DLOPEN_RE.finditer(code):
            var = m.group(1)
            add(var, "void *", CONFIDENCE_ASSIGNMENT, "assignment", "dlopen result")
            self.stats["assignment_inferences"] += 1

        # var = opendir(...) -> DIR *
        for m in _ASSIGN_OPENDIR_RE.finditer(code):
            var = m.group(1)
            add(var, "DIR *", CONFIDENCE_ASSIGNMENT, "assignment", "opendir result")
            self.stats["assignment_inferences"] += 1

        # var = fdopen(...) -> FILE *
        for m in _ASSIGN_FDOPEN_RE.finditer(code):
            var = m.group(1)
            add(var, "FILE *", CONFIDENCE_ASSIGNMENT, "assignment", "fdopen result")
            self.stats["assignment_inferences"] += 1

        # var = popen(...) -> FILE *
        for m in _ASSIGN_POPEN_RE.finditer(code):
            var = m.group(1)
            add(var, "FILE *", CONFIDENCE_ASSIGNMENT, "assignment", "popen result")
            self.stats["assignment_inferences"] += 1

        # var = tmpfile() -> FILE *
        for m in _ASSIGN_TMPFILE_RE.finditer(code):
            var = m.group(1)
            add(var, "FILE *", CONFIDENCE_ASSIGNMENT, "assignment", "tmpfile result")
            self.stats["assignment_inferences"] += 1

    def _infer_casts(
        self,
        code: str,
        add: Any,
    ) -> None:
        """Explicit cast pattern'lerinden tip cikar."""
        # var = (TYPE)expr -- direct cast
        for m in _EXPLICIT_CAST_RE.finditer(code):
            var = m.group(1)
            cast_type = m.group(2).strip()
            # undefined ve void gibi non-informative cast'leri atla
            if cast_type.startswith("undefined") or cast_type == "void":
                continue
            add(var, cast_type, CONFIDENCE_CAST, "cast", f"explicit cast to {cast_type}")
            self.stats["cast_inferences"] += 1

        # *(TYPE *)(var + offset) -- indirect type
        for m in _CAST_DEREF_RE.finditer(code):
            var = m.group("var")
            # var burada bir base pointer -- tipi struct/void* olmali
            add(var, "void *", CONFIDENCE_CAST, "cast", "base pointer in cast dereference")
            self.stats["cast_inferences"] += 1

    def _infer_string_literals(
        self,
        code: str,
        add: Any,
    ) -> None:
        """String literal atamasindan tip cikar."""
        for m in _STRING_LITERAL_RE.finditer(code):
            var = m.group(1)
            add(var, "char *", CONFIDENCE_STRING_LITERAL, "string_literal",
                "string literal assignment")

    def _infer_float_literals(
        self,
        code: str,
        add: Any,
    ) -> None:
        """Float literal atamasindan tip cikar."""
        for m in _FLOAT_LITERAL_RE.finditer(code):
            var = m.group(1)
            literal = m.group(2)
            # Basit heuristik: 'f' suffix yoksa double, varsa float
            if literal.endswith("f") or literal.endswith("F"):
                add(var, "float", CONFIDENCE_OPERATOR, "float_literal", f"float literal {literal}")
            else:
                add(var, "double", CONFIDENCE_OPERATOR, "float_literal", f"float literal {literal}")

    def _infer_sizeof(
        self,
        code: str,
        add: Any,
    ) -> None:
        """sizeof(var) kullanimindan tip cikar."""
        for m in _SIZEOF_RE.finditer(code):
            var = m.group(1)
            # sizeof(var) genellikle struct veya array icin kullanilir
            # Tek basina tip cikaramayiz ama "bu bir struct olabilir" ipucu
            add(var, "struct", CONFIDENCE_SIZEOF, "sizeof", "sizeof() argument")

    # ------------------------------------------------------------------
    # Yardimci
    # ------------------------------------------------------------------

    @staticmethod
    def _split_args_simple(args_str: str) -> list[str]:
        """Basit virgul split (nested parantezleri sayarak).

        Performans icin optimize: sadece parantez derinligi takip eder.
        """
        args: list[str] = []
        depth = 0
        current: list[str] = []
        for ch in args_str:
            if ch in "([{":
                depth += 1
                current.append(ch)
            elif ch in ")]}":
                depth -= 1
                current.append(ch)
            elif ch == "," and depth == 0:
                args.append("".join(current).strip())
                current = []
            else:
                current.append(ch)
        rest = "".join(current).strip()
        if rest:
            args.append(rest)
        return args

    def get_flat_type_map(self, result: XTrideResult) -> dict[str, str]:
        """XTrideResult'tan duz var -> type eslesmesi dondur.

        Entegrasyon katmani icin kolaylik fonksiyonu.
        """
        return {inf.var_name: inf.inferred_type for inf in result.inferences.values()}

    def merge_with_existing(
        self,
        xtride_result: XTrideResult,
        existing_types: dict[str, str],
    ) -> dict[str, str]:
        """XTRIDE tahminlerini mevcut tip bilgisiyle birlestirir.

        Kural:
            - Mevcut tip ``undefined*`` veya ``long`` ise -> XTRIDE tahmini tercih et.
            - Mevcut tip spesifik ise (FILE *, char *, struct X *) -> mevcut kalsin.
            - Mevcut tip yoksa -> XTRIDE tahmini ekle.

        Args:
            xtride_result: XTRIDE sonucu.
            existing_types: Mevcut {var: type} eslesmesi.

        Returns:
            Birlesmis {var: type} eslesmesi.
        """
        merged = dict(existing_types)

        # Spesifik olmayan (override edilecek) tipler
        _non_specific = {
            "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
            "long", "ulong", "int", "uint",
        }

        for var, inf in xtride_result.inferences.items():
            existing = merged.get(var, "")
            if not existing:
                # Mevcut tip yok -> XTRIDE tahmini ekle
                merged[var] = inf.inferred_type
            elif existing.strip() in _non_specific:
                # Non-specific -> XTRIDE override
                merged[var] = inf.inferred_type
            # else: mevcut spesifik tip korunur

        return merged

    def infer_types_batch(
        self,
        functions: dict[str, str],
    ) -> dict[str, XTrideResult]:
        """Birden fazla fonksiyon icin batch tip cikarimi.

        Args:
            functions: {func_name: func_code} eslesmesi.

        Returns:
            {func_name: XTrideResult} eslesmesi.
        """
        results: dict[str, XTrideResult] = {}
        for func_name, func_code in functions.items():
            results[func_name] = self.infer_types(func_code, func_name)
        return results

    @property
    def pattern_count(self) -> int:
        """Toplam n-gram pattern sayisi (API + operator + loop + ...)."""
        # API param tipleri (her fonksiyon-parametre cifti bir pattern)
        api_count = sum(len(v) for v in self._api_types.values())
        # Return tipleri
        ret_count = len(self._return_types)
        # Sabit regex pattern'ler
        regex_count = 25  # Yukaridaki tum regex pattern sayisi
        return api_count + ret_count + regex_count
